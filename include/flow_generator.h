#ifndef FLOW_GENERATOR_H
#define FLOW_GENERATOR_H

#include <pcap.h>
#include <map>
#include <string>
#include <filesystem>
#include <iostream>
#include <fstream>
#include <memory>
#include "basic_flow.h"
#include "basic_packet_info.h"
#include "flow_generator_listener.h"
#include "insert2csv.h"

class FlowGenerator
{
private:
    std::unique_ptr<FlowGeneratorListener> listener;
    std::map<std::string, BasicFlow> current_flows;
    std::map<int, BasicFlow> finished_flows;

    bool is_bidirectional;
    uint64_t flow_time_out;
    uint64_t flow_activity_time_out;
    uint64_t finished_flow_count;

public:
    FlowGenerator(bool is_bidirectional, uint64_t time_out, uint64_t activity_time_out)
        : is_bidirectional(is_bidirectional), flow_time_out(time_out),
          flow_activity_time_out(activity_time_out), finished_flow_count(0)
    {
        init();
    }

    void init()
    {
        current_flows.clear();
        finished_flows.clear();
        finished_flow_count = 0;
    }

    void add_listener(std::unique_ptr<FlowGeneratorListener> listener)
    {
        this->listener = std::move(listener);
    }

    void add_packet(BasicPacketInfo &packet)
    {
        if (packet.get_is_valid() == false)
        {
            return;
        }
        uint64_t current_timestamp = packet.get_timestamp();
        std::string id;

        if (current_flows.count(packet.fwd_flow_id()) || current_flows.count(packet.bwd_flow_id()))
        {
            id = current_flows.count(packet.fwd_flow_id()) ? packet.fwd_flow_id() : packet.bwd_flow_id();
            BasicFlow &flow = current_flows[id];

            if ((current_timestamp - flow.get_flow_start_time()) > flow_time_out)
            {
                finalize_flow(flow, id);
                current_flows[id] = BasicFlow(is_bidirectional, packet, flow.get_src(), flow.get_dst(), flow.get_src_port(), flow.get_dst_port(), flow_activity_time_out);
            }
            else if (packet.has_flag_fin() || packet.has_flag_rst())
            {
                handle_fin_rst_flags(flow, packet, id, current_timestamp);
            }
            else
            {
                handle_regular_packet(flow, packet, id, current_timestamp);
            }
        }
        else
        {
            current_flows[packet.fwd_flow_id()] = BasicFlow(is_bidirectional, packet, flow_activity_time_out);
        }
    }

    int dump_labeled_flow_based_features(const std::string &path, const std::string &filename, const std::string &header)
    {
        return dump_flows(path, filename, header, finished_flows) + dump_flows(path, filename, header, current_flows);
    }

    int dump_labed_current_flow(const std::string &path, const std::string &filename, const std::string &header)
    {
        return dump_flows(path, filename, header, current_flows);
    }

private:
    int get_flow_count()
    {
        return ++finished_flow_count;
    }

    void finalize_flow(BasicFlow &flow, const std::string &id)
    {
        if (flow.packet_count() > 1)
        {
            if (listener)
            {
                listener->on_flow_generated(flow);
            }
            else
            {
                finished_flows[get_flow_count()] = flow;
            }
        }
        current_flows.erase(id);
    }

    void handle_fin_rst_flags(BasicFlow &flow, BasicPacketInfo &packet, const std::string &id, uint64_t current_timestamp)
    {
        if (packet.has_flag_fin() && flow.get_src() == packet.get_src_ip() && flow.set_fwd_fin_flags() == 1)
        {
            if ((flow.get_fwd_fin_flags() + flow.get_bwd_fin_flags()) == 2)
            {
                flow.add_packet(packet);
                finalize_flow(flow, id);
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
            finalize_flow(flow, id);
        }
    }

    void handle_regular_packet(BasicFlow &flow, BasicPacketInfo &packet, const std::string &id, uint64_t current_timestamp)
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
            std::fstream file;
            if (!std::filesystem::exists(path + filename))
            {
                file.open(path + filename, std::ios::out | std::ios::app);
                file << header << std::endl;
            }
            else
            {
                file.open(path + filename, std::ios::out | std::ios::app);
            }

            if (!file.is_open())
            {
                std::cerr << "error: file not open" << std::endl;
                return total;
            }

            for (auto &[key, flow] : flows)
            {
                if (flow.packet_count() > 1)
                {
                    file << flow.dump_flow_based_features_ex() << std::endl;
                    total++;
                }
                else
                {
                    zero_pkt++;
                }
            }
            file.close();
            std::cout << "dump flows done, total: " << total << " zero pkt: " << zero_pkt << std::endl;
        }
        catch (const std::exception &e)
        {
            std::cerr << e.what() << '\n';
        }
        return total;
    }
};

#endif // FLOW_GENERATOR_H
