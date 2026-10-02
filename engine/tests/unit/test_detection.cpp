#include <gtest/gtest.h>
#include "intriqo/detection/port_scan_detector.hpp"
using namespace intriqo;
TEST(PortScanDetector, EmitsAfterConfiguredDistinctPorts) { detection::PortScanDetector d({10.0,3,3,events::Severity::HIGH}); auto t=Clock::now(); for(int i=0;i<2;i++){flow::NetworkFlow f;f.flow_id=i+1;f.key={{10,0,0,1},{10,0,0,2},40000,static_cast<Port>(80+i),Protocol::TCP};f.first_seen=f.last_seen=t; EXPECT_TRUE(d.evaluate(f,{}).empty());} flow::NetworkFlow f;f.flow_id=3;f.key={{10,0,0,1},{10,0,0,2},40000,82,Protocol::TCP};f.first_seen=f.last_seen=t; auto events=d.evaluate(f,{}); ASSERT_EQ(events.size(),1u); EXPECT_EQ(events[0].event_type,events::EventType::PORT_SCAN); EXPECT_FALSE(events[0].event_id.empty()); EXPECT_NE(events[0].to_json().find("PORT_SCAN"),std::string::npos); }
