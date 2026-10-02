#pragma once

#include "intriqo/events/security_event.hpp"
#include <string>

namespace intriqo::transport {

class SecurityEventSink {
public:
    virtual ~SecurityEventSink() = default;
    virtual bool submit(const events::SecurityEvent& event) noexcept = 0;
};

class FileEventSink final : public SecurityEventSink {
public:
    explicit FileEventSink(std::string path);
    bool submit(const events::SecurityEvent&) noexcept override;
private:
    std::string path_;
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
private:
    Config config_;
};

} // namespace intriqo::transport
