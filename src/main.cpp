#include <chrono>
#include <unordered_set>
#include <filesystem>
#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include "flow.h"
#include "preader.h"
#include "feature.h"

#define debug(x) std::cerr << #x << " = " << x
#define sp << " "
#define ln << "\n"

std::unordered_set<std::string> benigns; // benign labels

void finalize_flow(Flow &flow, std::map<std::string, Flow> &current_flows, std::map<int, Flow> &finished_flows, int &finished_flow_count)
{
    if (flow.packet_count() > 1)
    {
        finished_flows[++finished_flow_count] = flow;
    }
    current_flows.erase(flow.get_flow_id());
}

void handle_fin_rst_flags(Flow &flow, Packet &packet, const std::string &id, uint64_t current_timestamp, uint64_t flow_activity_time_out, std::map<std::string, Flow> &current_flows, std::map<int, Flow> &finished_flows, int &finished_flow_count)
{
    if (packet.has_flag_fin() && flow.get_src_ip() == packet.get_src_ip() && flow.set_fwd_fin_flags() == 1)
    {
        if ((flow.get_fwd_fin_flags() + flow.get_bwd_fin_flags()) == 2)
        {
            flow.add_packet(packet);
            finalize_flow(flow, current_flows, finished_flows, finished_flow_count);
        }
        else
        {
            flow.update_activate_idle_time(current_timestamp, flow_activity_time_out);
            flow.add_packet(packet);
            current_flows[id] = flow;
        }
    }
    else if (packet.has_flag_rst())
    {
        flow.add_packet(packet);
        finalize_flow(flow, current_flows, finished_flows, finished_flow_count);
    }
}

void handle_regular_packet(Flow &flow, Packet &packet, const std::string &id, uint64_t current_timestamp, uint64_t flow_activity_time_out, std::map<std::string, Flow> &current_flows)
{
    flow.update_activate_idle_time(current_timestamp, flow_activity_time_out);
    flow.add_packet(packet);
    current_flows[id] = flow;
}

template <typename FlowMap>
int dump_flows(const std::string &path, const std::string &filename, const std::string &header, FlowMap &flows)
{
    int total = 0;
    int zero_pkt = 0;

    try
    {
        std::ofstream file;
        std::string filepath = path + "/" + filename;
        if (!std::filesystem::exists(filepath))
        {
            file.open(filepath, std::ios::out | std::ios::app);
            file << header << std::endl;
        }
        else
        {
            file.open(filepath, std::ios::out | std::ios::app);
        }

        if (!file.is_open())
        {
            std::cerr << "Error: file not open" << std::endl;
            return total;
        }

        for (auto &[key, flow] : flows)
        {
            file << flow.dump_flow_based_features_ex() << std::endl;
            if (flow.packet_count() > 1) // only dump flows with more than 1 packet, but ddos maybe just 1 packet
            {
                // file << flow.dump_flow_based_features_ex() << std::endl;
                total++;
            }
            else
            {
                zero_pkt++;
            }
        }
        file.close();
        std::cout << "Dump flows done, total: " << total << " zero pkt: " << zero_pkt << std::endl;
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << '\n';
    }
    return total;
}

int main(int argc, char **argv)
{
    assert(argc >= 3);

    auto start = std::chrono::high_resolution_clock::now();

    // read pcap file
    PacketReader pkt_reader(argv[1], true, false);
    auto pkt_reader_end = std::chrono::high_resolution_clock::now();
    auto pkt_reader_elapsed = std::chrono::duration_cast<std::chrono::duration<double>>(pkt_reader_end - start);
    std::printf("Pcap file load elapsed time: %f\n", pkt_reader_elapsed.count());

    // write csv file
    std::string csv_path = argv[2];
    std::ofstream csv(csv_path);
    if (!csv.is_open())
    {
        std::cerr << "Error opening CSV file: " << csv_path << std::endl;
        return 1;
    }

    // read benign labels file
    FILE *benign = nullptr;
    bool has_label = (argc >= 4);
    std::printf("Processing (pcap file: %s, label file: %s) -> (csv file: %s)...\n", argv[1], has_label ? argv[3] : "none", argv[2]);

    if (has_label)
    {
        auto benign_start = std::chrono::high_resolution_clock::now();
        benign = fopen(argv[3], "r");
        if (benign == nullptr)
        {
            std::cerr << "Error opening label file: " << argv[3] << std::endl;
            return 1;
        }

        int flow_cnt;
        if (fscanf(benign, "%d", &flow_cnt) != EOF)
        {
            char flow_id[100];
            while (std::fscanf(benign, "%s", flow_id) != EOF)
            {
                benigns.insert(std::string(flow_id));
            }
        }
        fclose(benign);
        auto benign_end = std::chrono::high_resolution_clock::now();
        auto benign_elapsed = std::chrono::duration_cast<std::chrono::duration<double>>(benign_end - benign_start);
        std::printf("Label load elapsed time: %f\n", benign_elapsed.count());
    }

    auto flow_start = std::chrono::high_resolution_clock::now();
    FlowFeatureInfo flow_features;
    csv << flow_features.getHeader() << std::endl;

    std::map<std::string, Flow> current_flows;
    std::map<int, Flow> finished_flows;
    uint64_t flow_time_out = 60000000;          // 60 seconds timeout
    uint64_t flow_activity_time_out = 10000000; // 10 seconds activity timeout
    int finished_flow_count = 0;

    // Process packets and update flows
    Packet *packet;
    while ((packet = pkt_reader.next_packet()) != nullptr)
    {
        uint64_t current_timestamp = packet->get_timestamp();
        std::string id;

        if (current_flows.count(packet->fwd_flow_id()) || current_flows.count(packet->bwd_flow_id()))
        {
            id = current_flows.count(packet->fwd_flow_id()) ? packet->fwd_flow_id() : packet->bwd_flow_id();
            Flow &flow = current_flows[id];

            if ((current_timestamp - flow.get_flow_start_time()) > flow_time_out)
            {
                finalize_flow(flow, current_flows, finished_flows, finished_flow_count);
                current_flows[id] = Flow(true, *packet, flow_activity_time_out);
            }
            else if (packet->has_flag_fin() || packet->has_flag_rst())
            {
                handle_fin_rst_flags(flow, *packet, id, current_timestamp, flow_activity_time_out, current_flows, finished_flows, finished_flow_count);
            }
            else
            {
                handle_regular_packet(flow, *packet, id, current_timestamp, flow_activity_time_out, current_flows);
            }
        }
        else
        {
            current_flows[packet->fwd_flow_id()] = Flow(true, *packet, flow_activity_time_out);
        }

        // Set label for the flow
        /// TODO: Maybe the label has some relation with the flow timestamp
        auto flow_it = current_flows.find(packet->fwd_flow_id());
        if (flow_it != current_flows.end())
        {
            if (has_label)
                flow_it->second.set_label(benigns.count(flow_it->first) ? "BENIGN" : "ATTACK");
            else
                flow_it->second.set_label("UNKNOWN");
        }
    }

    // Dump all flows to CSV
    int current_flow_total = dump_flows(".", csv_path, flow_features.getHeader(), current_flows);
    int finished_flow_total = dump_flows(".", csv_path, flow_features.getHeader(), finished_flows);

    std::cout << "Current flows: " << current_flow_total << ", Finished flows: " << finished_flow_total << std::endl;

    auto flow_end = std::chrono::high_resolution_clock::now();
    auto flow_elapsed = std::chrono::duration_cast<std::chrono::duration<double>>(flow_end - flow_start);
    std::printf("Flow processing elapsed time: %f\n", flow_elapsed.count());

    auto end = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::duration<double>>(end - start);
    std::printf("Elapsed time: %f\n", elapsed.count());
    std::printf("Finished processing %s\n", argv[1]);

    csv.close();
    return 0;
}
