/// Unit tests for intriqo::flow types.

#include <gtest/gtest.h>
#include "intriqo/flow/flow.hpp"

using namespace intriqo;
using namespace intriqo::flow;

TEST(FlowKey, EqualityByAllFields) {
    FlowKey a{{{10,0,0,1}}, {{10,0,0,2}}, 12345, 80, Protocol::TCP};
    FlowKey b{{{10,0,0,1}}, {{10,0,0,2}}, 12345, 80, Protocol::TCP};
    FlowKey c{{{10,0,0,1}}, {{10,0,0,2}}, 12345, 81, Protocol::TCP};  // different dst_port
    EXPECT_EQ(a, b);
    EXPECT_NE(a, c);
}

TEST(NetworkFlow, DefaultCountersAreZero) {
    NetworkFlow f;
    EXPECT_EQ(f.packet_count, 0u);
    EXPECT_EQ(f.byte_count,   0u);
}

TEST(FlowState, AllVariantsExist) {
    // Compilation test — ensures the enum is complete
    [[maybe_unused]] FlowState s1 = FlowState::ACTIVE;
    [[maybe_unused]] FlowState s2 = FlowState::EXPIRED;
    [[maybe_unused]] FlowState s3 = FlowState::FINISHED;
}
