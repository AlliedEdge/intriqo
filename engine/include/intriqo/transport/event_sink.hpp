#pragma once

#include "intriqo/events/security_event.hpp"
#include <string>
#include <mutex>

namespace intriqo::transport {

class SecurityEventSink {
public:
    virtual ~SecurityEventSink() = default;
    virtual bool submit(const events::SecurityEvent& event) noexcept = 0;
    virtual bool prepare() noexcept { return true; }
    virtual bool flush() noexcept { return true; }
    [[nodiscard]] virtual std::string error() const { return {}; }
};

class FileEventSink final : public SecurityEventSink {
public:
    explicit FileEventSink(std::string path);
    bool prepare() noexcept override;
    bool submit(const events::SecurityEvent&) noexcept override;
    [[nodiscard]] std::string error() const override;
private:
    std::string path_;
    mutable std::mutex mutex_;
    std::string error_;
};

class HttpEventSink final : public SecurityEventSink {
public:
    struct Config {
        std::string url{"http://127.0.0.1:8000/api/v1/events"};
        long timeout_seconds{3};
        std::string bearer_token;
    };
    HttpEventSink();
    explicit HttpEventSink(Config config);
    bool submit(const events::SecurityEvent&) noexcept override;
    [[nodiscard]] long last_status_code() const noexcept;
    [[nodiscard]] std::string last_error() const;
    [[nodiscard]] std::string error() const override;
private:
    Config config_;
    std::mutex submit_mutex_;
    mutable std::mutex mutex_;
    long last_status_code_{0};
    std::string last_error_;
};

} // namespace intriqo::transport
