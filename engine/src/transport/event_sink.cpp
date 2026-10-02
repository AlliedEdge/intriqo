#include "intriqo/transport/event_sink.hpp"
#include <fstream>
#include <regex>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

namespace intriqo::transport {

FileEventSink::FileEventSink(std::string p): path_(std::move(p)) {}
bool FileEventSink::submit(const events::SecurityEvent& e) noexcept {
    try { std::ofstream out(path_, std::ios::app); if (!out) return false; out << e.to_json() << '\n'; return static_cast<bool>(out); }
    catch (...) { return false; }
}

HttpEventSink::HttpEventSink(): config_{} {}
HttpEventSink::HttpEventSink(Config c): config_(std::move(c)) {}
long HttpEventSink::last_status_code() const noexcept { std::lock_guard lock(mutex_); return last_status_code_; }
std::string HttpEventSink::last_error() const { std::lock_guard lock(mutex_); return last_error_; }

bool HttpEventSink::submit(const events::SecurityEvent& e) noexcept {
    try {
        { std::lock_guard lock(mutex_); last_status_code_ = 0; last_error_.clear(); }
        auto fail = [&](std::string message, long status = 0) noexcept {
            std::lock_guard lock(mutex_); last_status_code_ = status; last_error_ = std::move(message); return false;
        };
        std::regex r(R"(^http://([^/:]+)(?::([0-9]+))?(\/.*)$)");
        std::smatch match;
        if (!std::regex_match(config_.url, match, r)) return fail("unsupported or invalid HTTP URL");
        std::string host = match[1], port = match[2].matched ? match[2].str() : "80", path = match[3];
        addrinfo hints{}; hints.ai_socktype = SOCK_STREAM; addrinfo* result = nullptr;
        if (getaddrinfo(host.c_str(), port.c_str(), &hints, &result) != 0) return fail("DNS resolution failed");
        int fd = -1;
        for (auto* item = result; item; item = item->ai_next) {
            fd = socket(item->ai_family, item->ai_socktype, item->ai_protocol);
            if (fd >= 0 && connect(fd, item->ai_addr, item->ai_addrlen) == 0) break;
            if (fd >= 0) { close(fd); fd = -1; }
        }
        freeaddrinfo(result);
        if (fd < 0) return fail("connection failed");
        timeval timeout{config_.timeout_seconds, 0};
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        const auto body = e.to_json();
        std::string request = "POST " + path + " HTTP/1.1\r\nHost: " + host +
            "\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(body.size()) +
            "\r\nConnection: close\r\n";
        if (!config_.bearer_token.empty()) request += "Authorization: Bearer " + config_.bearer_token + "\r\n";
        request += "\r\n" + body;
        std::size_t sent = 0;
        while (sent < request.size()) {
            const auto n = send(fd, request.data() + sent, request.size() - sent, 0);
            if (n <= 0) { close(fd); return fail("request send failed"); }
            sent += static_cast<std::size_t>(n);
        }
        char buffer[256]{};
        const auto received = recv(fd, buffer, sizeof(buffer) - 1, 0);
        close(fd);
        if (received < 12) return fail("invalid HTTP response");
        const std::string response(buffer, static_cast<std::size_t>(received));
        const auto first_space = response.find(' ');
        const auto second_space = first_space == std::string::npos ? std::string::npos : response.find(' ', first_space + 1);
        if (first_space == std::string::npos || second_space == std::string::npos) return fail("invalid HTTP status line");
        long status = 0;
        try { status = std::stol(response.substr(first_space + 1, second_space - first_space - 1)); }
        catch (...) { return fail("invalid HTTP status code"); }
        if (status < 200 || status >= 300) return fail("Control Plane returned HTTP " + std::to_string(status), status);
        { std::lock_guard lock(mutex_); last_status_code_ = status; }
        return true;
    } catch (...) {
        std::lock_guard lock(mutex_); last_error_ = "unexpected transport error"; return false;
    }
}
}
