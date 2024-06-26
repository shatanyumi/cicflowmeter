#include <gtest/gtest.h>
#include "flow.h"
#include "packet.h"

// Test case to check the constructor and initial parameter values
TEST(FlowTest, ConstructorTest)
{
    Packet packet("192.168.1.1", "192.168.1.2", 12345, 80, 6, 1000);
    Flow flow(true, packet);

    EXPECT_EQ(flow.get_src_ip(), "192.168.1.1");
    EXPECT_EQ(flow.get_dst_ip(), "192.168.1.2");
    EXPECT_EQ(flow.get_src_port(), 12345);
    EXPECT_EQ(flow.get_dst_port(), 80);
    EXPECT_EQ(flow.get_protocol(), 6);
    EXPECT_EQ(flow.get_flow_start_time(), 1000);
}

// Test case to check the addition of packets and calculation of statistics
TEST(FlowTest, AddPacketTest)
{
    Packet packet1("192.168.1.1", "192.168.1.2", 12345, 80, 6, 1000);
    Packet packet2("192.168.1.2", "192.168.1.1", 80, 12345, 6, 2000);
    Flow flow(true, packet1);
    flow.add_packet(packet2);

    EXPECT_EQ(flow.get_fwd_pkt_stats().get_n(), 1);
    EXPECT_EQ(flow.get_bwd_pkt_stats().get_n(), 1);
    EXPECT_EQ(flow.get_duration(), 1000);
}

// Test case to check the dumping of flow-based features
TEST(FlowTest, DumpFlowBasedFeaturesTest)
{
    Packet packet1("192.168.1.1", "192.168.1.2", 12345, 80, 6, 1000);
    Packet packet2("192.168.1.2", "192.168.1.1", 80, 12345, 6, 2000);
    Flow flow(true, packet1);
    flow.add_packet(packet2);

    std::string expected_output = "Flow ID,Src IP,Src Port,Dst IP,Dst Port,Protocol,Timestamp,Flow Duration,Tot Fwd Pkts,Tot Bwd Pkts,TotLen Fwd Pkts,TotLen Bwd Pkts,Fwd Pkt Len Max,Fwd Pkt Len Min,Fwd Pkt Len Mean,Fwd Pkt Len Std,Bwd Pkt Len Max,Bwd Pkt Len Min,Bwd Pkt Len Mean,Bwd Pkt Len Std,Flow Byts/s,Flow Pkts/s,Flow IAT Mean,Flow IAT Std,Flow IAT Max,Flow IAT Min,Fwd IAT Tot,Fwd IAT Mean,Fwd IAT Std,Fwd IAT Max,Fwd IAT Min,Bwd IAT Tot,Bwd IAT Mean,Bwd IAT Std,Bwd IAT Max,Bwd IAT Min,Fwd PSH Flags,Bwd PSH Flags,Fwd URG Flags,Bwd URG Flags,Fwd Header Len,Bwd Header Len,Fwd Pkts/s,Bwd Pkts/s,Pkt Len Min,Pkt Len Max,Pkt Len Mean,Pkt Len Std,Pkt Len Var,FIN Flag Cnt,SYN Flag Cnt,RST Flag Cnt,PSH Flag Cnt,ACK Flag Cnt,URG Flag Cnt,CWE Flag Count,ECE Flag Cnt,Down/Up Ratio,Pkt Size Avg,Fwd Seg Size Avg,Bwd Seg Size Avg,Fwd Byts/b Avg,Fwd Pkts/b Avg,Fwd Blk Rate Avg,Bwd Byts/b Avg,Bwd Pkts/b Avg,Bwd Blk Rate Avg,Subflow Fwd Pkts,Subflow Fwd Byts,Subflow Bwd Pkts,Subflow Bwd Byts,Init Fwd Win Byts,Init Bwd Win Byts,Fwd Act Data Pkts,Fwd Seg Size Min,Active Mean,Active Std,Active Max,Active Min,Idle Mean,Idle Std,Idle Max,Idle Min,Label";

    std::string dump = flow.dump_flow_based_features();
    EXPECT_NE(dump, "");
}

// Test case to check the handling of flags
TEST(FlowTest, FlagHandlingTest)
{
    Packet packet("192.168.1.1", "192.168.1.2", 12345, 80, 6, 1000);
    packet.set_flag_fin(true);
    Flow flow(true, packet);

    EXPECT_EQ(flow.get_flag_counts("FIN"), 1);
    EXPECT_EQ(flow.get_flag_counts("SYN"), 0);
    EXPECT_EQ(flow.get_flag_counts("RST"), 0);
}

// Test case to check the subflow and bulk features
TEST(FlowTest, SubflowBulkFeaturesTest)
{
    Packet packet1("192.168.1.1", "192.168.1.2", 12345, 80, 6, 1000);
    Packet packet2("192.168.1.2", "192.168.1.1", 80, 12345, 6, 2000);
    Flow flow(true, packet1);
    flow.add_packet(packet2);

    EXPECT_EQ(flow.get_subflow_fwd_bytes(), 0);
    EXPECT_EQ(flow.get_subflow_fwd_packets(), 0);
    EXPECT_EQ(flow.get_subflow_bwd_bytes(), 0);
    EXPECT_EQ(flow.get_subflow_bwd_packets(), 0);
}
