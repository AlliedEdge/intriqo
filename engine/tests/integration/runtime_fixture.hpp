#pragma once
#include "intriqo/capture/capture.hpp"
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <unistd.h>

namespace runtime_test {
using namespace intriqo;
inline std::vector<std::vector<std::byte>> packets(std::size_t count = 10) {
    std::vector<std::vector<std::byte>> result;
    capture::SyntheticCaptureSource source({count, 10});
    source.set_callback([&](packet::PacketView p) { result.emplace_back(p.raw_bytes.begin(), p.raw_bytes.end()); });
    source.start();
    return result;
}
struct TempFile {
    std::filesystem::path path;
    TempFile() {
        auto pattern = (std::filesystem::temp_directory_path() / "intriqo-runtime-XXXXXX").string();
        const int fd = mkstemp(pattern.data());
        if (fd < 0) throw std::runtime_error("cannot create temporary test file");
        close(fd);
        path = pattern;
    }
    ~TempFile() { std::error_code error; std::filesystem::remove(path, error); }
};
inline void word(std::ostream& out, std::uint32_t value, unsigned bytes, bool little) {
    for (unsigned i = 0; i < bytes; ++i) {
        const auto shift = (little ? i : bytes - i - 1) * 8;
        out.put(static_cast<char>((value >> shift) & 255U));
    }
}
inline void pcap(const std::filesystem::path& path,
                 const std::vector<std::vector<std::byte>>& data,
                 std::uint32_t link = 1, bool little = true, bool nano = false,
                 std::uint32_t wire_extra = 0, std::uint32_t interval_seconds = 0) {
    std::ofstream out(path, std::ios::binary);
    word(out, nano ? 0xa1b23c4d : 0xa1b2c3d4, 4, little);
    word(out, 2, 2, little); word(out, 4, 2, little);
    word(out, 0, 4, little); word(out, 0, 4, little);
    word(out, 65535, 4, little); word(out, link, 4, little);
    std::uint32_t seconds = 1700000000;
    for (const auto& bytes : data) {
        word(out, seconds, 4, little); word(out, nano ? 123456789 : 123456, 4, little);
        word(out, static_cast<std::uint32_t>(bytes.size()), 4, little);
        word(out, static_cast<std::uint32_t>(bytes.size()) + wire_extra, 4, little);
        out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        seconds += interval_seconds;
    }
}
} // namespace runtime_test
