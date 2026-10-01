/// Unit tests for intriqo::features types.

#include <gtest/gtest.h>
#include "intriqo/features/features.hpp"

using namespace intriqo::features;

TEST(FlowFeatures, DefaultValuesAreZero) {
    FlowFeatures f;
    EXPECT_EQ(f.packet_count,       0u);
    EXPECT_EQ(f.byte_count,         0u);
    EXPECT_DOUBLE_EQ(f.duration_seconds, 0.0);
    EXPECT_DOUBLE_EQ(f.bytes_per_packet, 0.0);
    EXPECT_DOUBLE_EQ(f.packets_per_second, 0.0);
}
