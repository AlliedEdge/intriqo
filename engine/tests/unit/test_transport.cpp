#include <gtest/gtest.h>
#include "intriqo/transport/event_sink.hpp"
#include <filesystem>
using namespace intriqo;
TEST(EventSink, FileSinkWritesSerializedEvent) { auto path=std::filesystem::temp_directory_path()/"intriqo-event-test.jsonl"; transport::FileEventSink sink(path.string()); events::SecurityEvent e; e.event_id="test";e.event_type=events::EventType::PORT_SCAN;e.severity=events::Severity::LOW;e.timestamp=Clock::now();e.source_address={{1,2,3,4}};e.destination_address={{5,6,7,8}};EXPECT_TRUE(sink.submit(e));EXPECT_TRUE(std::filesystem::file_size(path)>0);std::filesystem::remove(path); }
TEST(EventSink, HttpFailureIsReportedWithoutThrowing) { transport::HttpEventSink sink({"http://127.0.0.1:1/api/v1/events",1,""}); events::SecurityEvent e; e.event_id="test"; EXPECT_FALSE(sink.submit(e)); }
