#include "intriqo/transport/event_sink.hpp"
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstring>
#include <fstream>
#include <limits>
#include <memory>
#include <regex>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

namespace intriqo::transport {
namespace {

class Socket {
public:
    explicit Socket(int fd = -1) noexcept : fd_(fd) {}
    ~Socket() { if (fd_ >= 0) ::close(fd_); }
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    [[nodiscard]] int get() const noexcept { return fd_; }
    void reset(int fd = -1) noexcept {
        if (fd_ >= 0) ::close(fd_);
        fd_ = fd;
    }
private:
    int fd_;
};

using Deadline = std::chrono::steady_clock::time_point;

bool wait_socket(int fd, short events, Deadline deadline) noexcept {
    for (;;) {
        const auto remaining = deadline - std::chrono::steady_clock::now();
        if (remaining <= std::chrono::steady_clock::duration::zero()) {
            errno = ETIMEDOUT;
            return false;
        }
        const auto milliseconds = std::chrono::ceil<std::chrono::milliseconds>(remaining).count();
        const int timeout = milliseconds > std::numeric_limits<int>::max()
            ? std::numeric_limits<int>::max() : static_cast<int>(milliseconds);
        pollfd descriptor{fd, events, 0};
        const int result = ::poll(&descriptor, 1, timeout);
        if (result < 0 && errno == EINTR) continue;
        if (result == 0) { errno = ETIMEDOUT; return false; }
        if (result < 0) return false;
        if (descriptor.revents & events) return true;
        errno = ECONNRESET;
        return false;
    }
}

std::string socket_error(const char* operation) {
    return std::string(operation) + ": " + std::strerror(errno);
}

} // namespace

FileEventSink::FileEventSink(std::string p): path_(std::move(p)) {}
bool FileEventSink::prepare() noexcept {
    std::lock_guard lock(mutex_);
    try {
        error_.clear();
        std::ofstream out(path_, std::ios::app);
        if (!out) { error_ = "cannot open event file: " + path_; return false; }
        out.close();
        if (!out) { error_ = "cannot close event file: " + path_; return false; }
        return true;
    } catch (...) {
        error_ = "unexpected event file initialization error";
        return false;
    }
}
bool FileEventSink::submit(const events::SecurityEvent& e) noexcept {
    std::lock_guard lock(mutex_);
    try {
        error_.clear();
        std::ofstream out(path_, std::ios::app);
        if (!out) { error_ = "cannot open event file: " + path_; return false; }
        out << e.to_json() << '\n';
        out.flush();
        if (!out) { error_ = "cannot write or flush event file: " + path_; return false; }
        out.close();
        if (!out) { error_ = "cannot close event file: " + path_; return false; }
        return true;
    } catch (...) {
        error_ = "unexpected event file write error";
        return false;
    }
}
std::string FileEventSink::error() const { std::lock_guard lock(mutex_); return error_; }

HttpEventSink::HttpEventSink(): config_{} {}
HttpEventSink::HttpEventSink(Config c): config_(std::move(c)) {}
long HttpEventSink::last_status_code() const noexcept { std::lock_guard lock(mutex_); return last_status_code_; }
std::string HttpEventSink::last_error() const { std::lock_guard lock(mutex_); return last_error_; }
std::string HttpEventSink::error() const { return last_error(); }

bool HttpEventSink::submit(const events::SecurityEvent& e) noexcept {
    std::lock_guard submit_lock(submit_mutex_);
    try {
        { std::lock_guard lock(mutex_); last_status_code_ = 0; last_error_.clear(); }
        auto fail = [&](std::string message, long status = 0) {
            std::lock_guard lock(mutex_); last_status_code_ = status; last_error_ = std::move(message); return false;
        };
        if (config_.timeout_seconds <= 0 ||
            config_.timeout_seconds > std::numeric_limits<int>::max() / 1000) {
            return fail("HTTP timeout must be positive and fit in milliseconds");
        }
        std::regex r(R"(^http://([^/:]+)(?::([0-9]+))?(\/.*)$)");
        std::smatch match;
        if (!std::regex_match(config_.url, match, r)) return fail("unsupported or invalid HTTP URL");
        std::string host = match[1], port = match[2].matched ? match[2].str() : "80", path = match[3];
        addrinfo hints{}; hints.ai_socktype = SOCK_STREAM; addrinfo* result = nullptr;
        const int lookup = getaddrinfo(host.c_str(), port.c_str(), &hints, &result);
        if (lookup != 0) return fail(std::string("DNS resolution failed: ") + gai_strerror(lookup));
        std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> addresses(result, freeaddrinfo);
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(config_.timeout_seconds);
        Socket connection;
        std::string connection_error = "connection failed";
        for (auto* item = addresses.get(); item; item = item->ai_next) {
            connection.reset(::socket(item->ai_family, item->ai_socktype, item->ai_protocol));
            if (connection.get() < 0) { connection_error = socket_error("socket creation failed"); continue; }
            const int flags = ::fcntl(connection.get(), F_GETFL, 0);
            if (flags < 0 || ::fcntl(connection.get(), F_SETFL, flags | O_NONBLOCK) < 0) {
                connection_error = socket_error("socket configuration failed");
                connection.reset();
                continue;
            }
#ifdef SO_NOSIGPIPE
            int no_sigpipe = 1;
            if (::setsockopt(connection.get(), SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe, sizeof(no_sigpipe)) != 0) {
                connection_error = socket_error("socket SIGPIPE configuration failed");
                connection.reset();
                continue;
            }
#endif
            if (::connect(connection.get(), item->ai_addr, item->ai_addrlen) == 0) break;
            if ((errno == EINPROGRESS || errno == EINTR) &&
                wait_socket(connection.get(), POLLOUT, deadline)) {
                int error = 0;
                socklen_t length = sizeof(error);
                if (::getsockopt(connection.get(), SOL_SOCKET, SO_ERROR, &error, &length) == 0) {
                    if (error == 0) break;
                    errno = error;
                }
            }
            connection_error = socket_error("connection failed");
            connection.reset();
            if (std::chrono::steady_clock::now() >= deadline) break;
        }
        if (connection.get() < 0) return fail(connection_error);
        const auto body = e.to_json();
        std::string request = "POST " + path + " HTTP/1.1\r\nHost: " + host +
            "\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(body.size()) +
            "\r\nConnection: close\r\n";
        if (!config_.bearer_token.empty()) request += "Authorization: Bearer " + config_.bearer_token + "\r\n";
        request += "\r\n" + body;
        std::size_t sent = 0;
        while (sent < request.size()) {
            if (!wait_socket(connection.get(), POLLOUT, deadline)) return fail(socket_error("request send failed"));
            int send_flags = 0;
#ifdef MSG_NOSIGNAL
            send_flags = MSG_NOSIGNAL;
#endif
            const auto n = ::send(connection.get(), request.data() + sent, request.size() - sent, send_flags);
            if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
            if (n <= 0) return fail(n == 0 ? "connection closed during request" : socket_error("request send failed"));
            sent += static_cast<std::size_t>(n);
        }
        std::string response;
        std::size_t line_end = std::string::npos;
        while ((line_end = response.find('\n')) == std::string::npos) {
            if (response.size() >= 4096) return fail("HTTP status line too long");
            if (!wait_socket(connection.get(), POLLIN, deadline)) return fail(socket_error("response receive failed"));
            char buffer[256];
            const auto received = ::recv(connection.get(), buffer, sizeof(buffer), 0);
            if (received < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
            if (received < 0) return fail(socket_error("response receive failed"));
            if (received == 0) return fail("connection closed before HTTP status line");
            response.append(buffer, static_cast<std::size_t>(received));
        }
        const std::string_view status_line(response.data(), line_end);
        if (status_line.size() < 12 ||
            !(status_line.starts_with("HTTP/1.0 ") || status_line.starts_with("HTTP/1.1 ")) ||
            (status_line.size() > 12 && status_line[12] != ' ' && status_line[12] != '\r')) {
            return fail("invalid HTTP status line");
        }
        long status = 0;
        const auto parsed = std::from_chars(status_line.data() + 9, status_line.data() + 12, status);
        if (parsed.ec != std::errc{} || parsed.ptr != status_line.data() + 12 || status < 100 || status > 599) {
            return fail("invalid HTTP status code");
        }
        if (status < 200 || status >= 300) return fail("Control Plane returned HTTP " + std::to_string(status), status);
        { std::lock_guard lock(mutex_); last_status_code_ = status; }
        return true;
    } catch (...) {
        std::lock_guard lock(mutex_); last_error_ = "unexpected transport error"; return false;
    }
}
}
