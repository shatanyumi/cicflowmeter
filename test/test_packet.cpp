#include <gtest/gtest.h>
#include "packet.h"

TEST(PacketTest, ConstructorTest) {
    Packet packet("192.168.1.1", "192.168.1.2", 12345, 80, 6, 1000);

    EXPECT_EQ(packet.get_src_ip(), "192.168.1.1");
    EXPECT_EQ(packet.get_dst_ip(), "192.168.1.2");
    EXPECT_EQ(packet.get_src_port(), 12345);
    EXPECT_EQ(packet.get_dst_port(), 80);
    EXPECT_EQ(packet.get_protocol(), 6);
    EXPECT_EQ(packet.get_timestamp(), 1000);
}

TEST(PacketTest, GenerateFlowIdTest) {
    Packet packet("192.168.1.1", "192.168.1.2", 12345, 80, 6, 1000);
    std::string flow_id = packet.generate_flow_id();

    EXPECT_EQ(flow_id, "192.168.1.1-192.168.1.2-12345-80-6");
}

TEST(PacketTest, FlowIdConsistencyTest) {
    Packet packet1("192.168.1.1", "192.168.1.2", 12345, 80, 6, 1000);
    Packet packet2("192.168.1.2", "192.168.1.1", 80, 12345, 6, 1000);

    std::string flow_id1 = packet1.generate_flow_id();
    std::string flow_id2 = packet2.generate_flow_id();

    EXPECT_EQ(flow_id1, flow_id2);
}