#include <gtest/gtest.h>
#include "flow_generator.h"
#include "basic_packet_info.h"
#include "basic_flow.h"
#include <memory>
#include <fstream>
#include <filesystem>

// 测试 FlowGenerator 的初始化
TEST(FlowGeneratorTest, Initialization)
{
    FlowGenerator flowGen(true, 60, 30);
    EXPECT_EQ(flowGen.dump_labeled_flow_based_features("", "test_flow_gen.txt", "header"), 0);
}

// 测试添加包
TEST(FlowGeneratorTest, AddPacket)
{
    FlowGenerator flowGen(true, 60, 30);
    BasicPacketInfo packet;
    flowGen.add_packet(packet);
    EXPECT_EQ(flowGen.dump_labeled_flow_based_features("", "test_add_pkt.txt", "header"), 0);
}

// 测试导出功能
TEST(FlowGeneratorTest, DumpFlows)
{
    FlowGenerator flowGen(true, 60, 30);
    BasicPacketInfo packet;
    flowGen.add_packet(packet);

    std::string path = "./";
    std::string filename = "test_flows.csv";
    std::string header = "Flow features header";

    int total = flowGen.dump_labeled_flow_based_features(path, filename, header);

    // 检查文件是否存在
    EXPECT_TRUE(std::filesystem::exists(path + filename));

    // 检查文件内容
    std::ifstream file(path + filename);
    std::string line;
    std::getline(file, line); // 读取标题行
    EXPECT_EQ(line, header);

    file.close();
    std::filesystem::remove(path + filename); // 删除测试文件
}