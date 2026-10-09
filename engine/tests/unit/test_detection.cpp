#include <gtest/gtest.h>
#include "intriqo/detection/port_scan_detector.hpp"
using namespace intriqo;
TEST(PortScanDetector, EmitsAfterConfiguredDistinctPorts) { detection::PortScanDetector d({10.0,3,3,events::Severity::HIGH}); auto t=Clock::now(); for(int i=0;i<2;i++){flow::NetworkFlow f;f.flow_id=i+1;f.key={{10,0,0,1},{10,0,0,2},40000,static_cast<Port>(80+i),Protocol::TCP};f.first_seen=f.last_seen=t; EXPECT_TRUE(d.evaluate(f,{}).empty());} flow::NetworkFlow f;f.flow_id=3;f.key={{10,0,0,1},{10,0,0,2},40000,82,Protocol::TCP};f.first_seen=f.last_seen=t; auto events=d.evaluate(f,{}); ASSERT_EQ(events.size(),1u); EXPECT_EQ(events[0].event_type,events::EventType::PORT_SCAN); EXPECT_FALSE(events[0].event_id.empty()); EXPECT_NE(events[0].to_json().find("PORT_SCAN"),std::string::npos); }

TEST(PortScanDetector, EmitsDistinctUdpScanAndIgnoresTcp) {
    detection::PortScanConfig config{10.0, 3, 3, events::Severity::HIGH};
    config.protocol = Protocol::UDP;
    detection::PortScanDetector detector(config);
    EXPECT_EQ(detector.name(), "udp_port_scan");
    const auto timestamp = Clock::now();
    for (FlowId id = 1; id <= 3; ++id) {
        flow::NetworkFlow flow;
        flow.flow_id = id;
        flow.key = {{10, 0, 0, 1}, {10, 0, 0, 2}, static_cast<Port>(45000 + id), static_cast<Port>(10000 + id), Protocol::TCP};
        flow.first_seen = flow.last_seen = timestamp;
        EXPECT_TRUE(detector.evaluate(flow, {}).empty());
    }
    std::vector<events::SecurityEvent> emitted;
    for (FlowId id = 4; id <= 6; ++id) {
        flow::NetworkFlow flow;
        flow.flow_id = id;
        flow.key = {{10, 0, 0, 1}, {10, 0, 0, 2}, static_cast<Port>(45000 + id), static_cast<Port>(10000 + id), Protocol::UDP};
        flow.first_seen = flow.last_seen = timestamp;
        auto events = detector.evaluate(flow, {});
        emitted.insert(emitted.end(), events.begin(), events.end());
    }
    ASSERT_EQ(emitted.size(), 1u);
    EXPECT_EQ(emitted.front().event_type, events::EventType::UDP_SCAN);
    EXPECT_NE(emitted.front().to_json().find("udp_port_scan"), std::string::npos);
    EXPECT_NE(emitted.front().to_json().find("UDP"), std::string::npos);
}
