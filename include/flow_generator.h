// flow generator class
#ifndef FLOW_GENERATOR_H
#define FLOW_GENERATOR_H

#include <pcap.h>
#include <map>
#include <string>
#include "basic_flow.h"
#include "basic_packet_info.h"
#include "flow_generator_listener.h"
#include "insert2csv.h"

class FlowGenerator
{
    // total 85 colums
    /*
     * public static final String timeBasedHeader =
     * "Flow ID, Source IP, Source Port, Destination IP, Destination Port, Protocol, "
     * + "Timestamp, Flow Duration, Total Fwd Packets, Total Backward Packets,"
     * + "Total Length of Fwd Packets, Total Length of Bwd Packets, "
     * +
     * "Fwd Packet Length Max, Fwd Packet Length Min, Fwd Packet Length Mean, Fwd Packet Length Std,"
     * +
     * "Bwd Packet Length Max, Bwd Packet Length Min, Bwd Packet Length Mean, Bwd Packet Length Std,"
     * +
     * "Flow Bytes/s, Flow Packets/s, Flow IAT Mean, Flow IAT Std, Flow IAT Max, Flow IAT Min,"
     * + "Fwd IAT Total, Fwd IAT Mean, Fwd IAT Std, Fwd IAT Max, Fwd IAT Min,"
     * + "Bwd IAT Total, Bwd IAT Mean, Bwd IAT Std, Bwd IAT Max, Bwd IAT Min,"
     * +
     * "Fwd PSH Flags, Bwd PSH Flags, Fwd URG Flags, Bwd URG Flags, Fwd Header Length, Bwd Header Length,"
     * +
     * "Fwd Packets/s, Bwd Packets/s, Min Packet Length, Max Packet Length, Packet Length Mean, Packet Length Std, Packet Length Variance,"
     * +
     * "FIN Flag Count, SYN Flag Count, RST Flag Count, PSH Flag Count, ACK Flag Count, URG Flag Count, "
     * +
     * "CWR Flag Count, ECE Flag Count, Down/Up Ratio, Average Packet Size, Avg Fwd Segment Size, Avg Bwd Segment Size, Fwd Header Length,"
     * +
     * "Fwd Avg Bytes/Bulk, Fwd Avg Packets/Bulk, Fwd Avg Bulk Rate, Bwd Avg Bytes/Bulk, Bwd Avg Packets/Bulk,"
     * + "Bwd Avg Bulk Rate,"
     * +
     * "Subflow Fwd Packets, Subflow Fwd Bytes, Subflow Bwd Packets, Subflow Bwd Bytes,"
     * +
     * "Init_Win_bytes_forward, Init_Win_bytes_backward, act_data_pkt_fwd, min_seg_size_forward,"
     * + "Active Mean, Active Std, Active Max, Active Min,"
     * + "Idle Mean, Idle Std, Idle Max, Idle Min, Label";
     */

    // 40/86
private:
    FlowGeneratorListener *listener;
    std::map<std::string, BasicFlow> current_flows;
    std::map<int, BasicFlow> finished_flows;

    bool is_bidirectional;
    uint64_t flow_time_out;
    uint64_t flow_activity_time_out;
    uint64_t finished_flow_count;

    FlowGenerator(bool is_bidirectional, uint64_t time_out, uint64_t activity_time_out)
        : is_bidirectional(is_bidirectional), flow_time_out(time_out),
          flow_activity_time_out(activity_time_out)
    {
        init();
    }

public:
    void init()
    {
        current_flows = std::map<std::string, BasicFlow>();
        finished_flows = std::map<int, BasicFlow>();
        finished_flow_count = 0;
    }

    void add_listener(FlowGeneratorListener *listener)
    {
        this->listener = listener;
    }

    void add_packet(BasicPacketInfo packet)
    {
        BasicFlow flow;
        uint64_t current_timestamp = packet.get_timestamp();
        std::string id;

        if (this->current_flows.count(packet.fwd_flow_id()) || this->current_flows.count(packet.bwd_flow_id()))
        {
            if (this->current_flows.count(packet.fwd_flow_id()))
            {
                id = packet.fwd_flow_id();
            }
            else
            {
                id = packet.bwd_flow_id();
            }

            flow = this->current_flows[id];
            // Flow finished due flowtimeout:
            // 1.- we move the flow to finished flow list
            // 2.- we eliminate the flow from the current flow list
            // 3.- we create a new flow with the packet-in-process
            if ((current_timestamp - flow.get_flow_start_time()) > this->flow_time_out)
            {
                if (flow.packet_count() > 1)
                {
                    if (listener != nullptr)
                    {
                        listener->on_flow_generated(flow);
                    }
                    else
                    {
                        finished_flows[get_flow_count()] = flow;
                    }
                }

                current_flows.erase(id);
                current_flows[id] = BasicFlow(is_bidirectional, packet,
                                              flow.get_src(), flow.get_dst(),
                                              flow.get_src_port(), flow.get_dst_port(),
                                              this->flow_activity_time_out);

                int cfsize = current_flows.size();
                if (cfsize % 50 == 0)
                {
                    std::cout << "debug: timeout current has " << cfsize << " flows" << std::endl;
                }

                // // Flow finished due FIN flag (tcp only):
                // // 1.- we add the packet-in-process to the flow (it is the last packet)
                // // 2.- we move the flow to finished flow list
                // // 3.- we eliminate the flow from the current flow list
                // }else if(packet.hasFlagFIN()){
                // logger.debug("FlagFIN current has {} flow",currentFlows.size());
                // flow.addPacket(packet);
                // if (mListener != null) {
                // mListener.onFlowGenerated(flow);
                // } else {
                // finishedFlows.put(getFlowCount(), flow);
                // }
                // currentFlows.remove(id);
            }
            else if (packet.has_flag_fin())
            {
                // Forward flow
                if (flow.get_src() == packet.get_src_ip())
                {
                    // How many forward FIN received?
                    if (flow.set_fwd_fin_flags() == 1)
                    {
                        // Flow finished due FIN flag (tcp only)?:
                        // 1.- we add the packet-in-process to the flow (it is the last packet)
                        // 2.- we move the flow to finished flow list
                        // 3.- we eliminate the flow from the current flow list
                        if ((flow.get_bwd_fin_flags() + flow.get_bwd_fin_flags()) == 2)
                        {
                            std::cout << "debug: flag fin current has " << current_flows.size() << " flows" << std::endl;
                            flow.add_packet(packet);
                            if (listener != nullptr)
                            {
                                listener->on_flow_generated(flow);
                            }
                            else
                            {
                                finished_flows[get_flow_count()] = flow;
                            }
                            current_flows.erase(id);
                            // backward flow finished
                        }
                        else
                        {
                            std::cout << "debug: backward flow closed due to fin flag" << std::endl;
                            flow.update_activate_idle_time(current_timestamp, this->flow_activity_time_out);
                            flow.add_packet(packet);
                            current_flows[id] = flow;
                        }
                    }
                    else
                    {
                        // some error
                        // todo review what to do with the packet
                        std::cout << "error: backward flow received " << flow.get_bwd_fin_flags() << " fin flag" << std::endl;
                    }
                }
                // Flow finished due RST flag (tcp only):
                // 1.- we add the packet-in-process to the flow (it is the last packet)
                // 2.- we move the flow to finished flow list
                // 3.- we eliminate the flow from the current flow list
            }
            else if (packet.has_flag_rst())
            {
                std::cout << "debug: flag rst current has " << current_flows.size() << " flows" << std::endl;
                flow.add_packet(packet);
                if (listener != nullptr)
                {
                    listener->on_flow_generated(flow);
                }
                else
                {
                    finished_flows[get_flow_count()] = flow;
                }
                current_flows.erase(id);
            }
            else
            {
                //
                // Forward Flow and fwdFIN = 0
                //
                if (flow.get_src() == packet.get_src_ip() && flow.get_fwd_fin_flags() == 0)
                {
                    flow.update_activate_idle_time(current_timestamp, this->flow_activity_time_out);
                    flow.add_packet(packet);
                    current_flows[id] = flow;
                    //
                    // Backward Flow and bwdFIN = 0
                    //
                }
                else if (flow.get_bwd_fin_flags() == 0)
                {
                    flow.update_activate_idle_time(current_timestamp, this->flow_activity_time_out);
                    flow.add_packet(packet);
                    current_flows[id] = flow;
                    //
                    // FLOW already closed!!!
                    //
                }
                else
                {
                    std::cout << "error: flow already closed fwd fin " << flow.get_fwd_fin_flags() << " bwd fin " << flow.get_bwd_fin_flags() << std::endl;
                }
            }
        }
        else
        {
            current_flows[packet.fwd_flow_id()] = BasicFlow(is_bidirectional, packet,
                                                            this->flow_activity_time_out);
        }
    }

    void dump_labeled_flow_based_features(std::string path, std::string filename, std::string header)
    {
        
    }

private:
    int get_flow_count()
    {
        finished_flow_count++;
        return finished_flow_count;
    }
};

#endif // FLOW_GENERATOR_H