#ifndef BASIC_FLOW_H
#define BASIC_FLOW_H

#include <vector>
#include <unordered_map>
#include <string>
#include <cmath>
#include <iostream>
#include <algorithm>
#include <memory>
#include <cstring>
#include <chrono>
#include <iomanip>
#include <numeric>
#include "basic_packet_info.h" // Include the BasicPacketInfo header
#include "flow_feature.h"      // Include the FlowFeature header

class SummaryStatistics
{
private:
    std::vector<double> data;

public:
    void add_value(double value)
    {
        data.push_back(value);
    }

    double get_sum() const
    {
        return std::accumulate(data.begin(), data.end(), 0.0);
    }

    double get_mean() const
    {
        if (data.empty())
            return 0;
        return get_sum() / data.size();
    }

    double get_std() const
    {
        if (data.size() < 2)
            return 0;
        double mean = get_mean();
        double sq_sum = std::inner_product(data.begin(), data.end(), data.begin(), 0.0);
    }

    double get_max() const
    {
        if (data.empty())
            return 0;
        return *std::max_element(data.begin(), data.end());
    }

    double get_min() const
    {
        if (data.empty())
            return 0;
        return *std::min_element(data.begin(), data.end());
    }

    size_t get_n() const
    {
        return data.size();
    }

    double get_variance() const
    {
        if (data.size() < 2)
            return 0;
        double mean = get_mean();
        double sq_sum = std::inner_product(data.begin(), data.end(), data.begin(), 0.0);
        return (sq_sum / data.size()) - (mean * mean);
    }
};

class MutableInt
{
public:
    int value = 0;
    void increment()
    {
        value++;
    }
    int get() const
    {
        return value;
    }
};

class BasicFlow
{
    static constexpr char separator = ',';
    SummaryStatistics fwd_pkt_stats;
    SummaryStatistics bwd_pkt_stats;
    std::vector<BasicPacketInfo> forward;
    std::vector<BasicPacketInfo> backward;

    uint64_t fwd_bytes = 0;
    uint64_t bwd_bytes = 0;
    uint64_t fwd_header_bytes = 0;
    uint64_t bwd_header_bytes = 0;
    bool is_bidirectional;
    std::unordered_map<std::string, MutableInt> flag_counts;

    int fwd_psh_cnt = 0;
    int bwd_psh_cnt = 0;
    int fwd_urg_cnt = 0;
    int bwd_urg_cnt = 0;

    uint64_t act_data_pkt_fwd = 0;
    uint64_t min_seg_size_fwd = 0;
    uint64_t init_win_bytes_fwd = 0;
    uint64_t init_win_bytes_bwd = 0;

    std::string src;
    std::string dst;
    int src_port;
    int dst_port;
    int protocol;

    uint64_t flow_start_time;
    uint64_t flow_end_time;
    uint64_t start_active_time;
    uint64_t end_active_time;

    std::string flow_id;

    SummaryStatistics flow_IAT;
    SummaryStatistics fwd_IAT;
    SummaryStatistics bwd_IAT;
    SummaryStatistics flow_length_stats;
    SummaryStatistics flow_active;
    SummaryStatistics flow_idle;

    uint64_t flow_last_seen;
    uint64_t fwd_last_seen;
    uint64_t bwd_last_seen;
    /*******************************************/
    uint64_t subflow_last_packet_timestamp = -1;
    int subflow_count = 0;
    uint64_t subflow_ac_helper = 0;
    /*******************************************/
    uint64_t fwd_bulk_duration = 0;
    uint64_t fwd_bulk_packet_count = 0;
    uint64_t fwd_bulk_size_total = 0;
    uint64_t fwd_bulk_state_count = 0;
    uint64_t fwd_bulk_packet_count_helper = 0;
    uint64_t fwd_bulk_start_helper = 0;
    uint64_t fwd_bulk_size_helper = 0;
    uint64_t fwd_bulk_last_timestamp = 0;
    /*******************************************/
    uint64_t bwd_bulk_duration = 0;
    uint64_t bwd_bulk_packet_count = 0;
    uint64_t bwd_bulk_size_total = 0;
    uint64_t bwd_bulk_state_count = 0;
    uint64_t bwd_bulk_packet_count_helper = 0;
    uint64_t bwd_bulk_start_helper = 0;
    uint64_t bwd_bulk_size_helper = 0;
    uint64_t bwd_bulk_last_timestamp = 0;

public:
    BasicFlow(bool isBidirectional, BasicPacketInfo &packet, const std::string &flow_src, const std::string &flow_dst, int src_port, int dst_port, int protocol)
        : is_bidirectional(isBidirectional), src(flow_src), dst(flow_dst), src_port(src_port), dst_port(dst_port), protocol(protocol)
    {
        init_parameters();
        first_packet(packet);
    }

    BasicFlow(bool isBidirectional, BasicPacketInfo &packet)
        : is_bidirectional(isBidirectional)
    {
        init_parameters();
        first_packet(packet);
    }

    BasicFlow(BasicPacketInfo &packet)
        : is_bidirectional(true)
    {
        init_parameters();
        first_packet(packet);
    }

    void init_parameters()
    {
        forward = std::vector<BasicPacketInfo>();                    // Initialize the forward vector
        backward = std::vector<BasicPacketInfo>();                   // Initialize the backward vector
        flow_IAT = SummaryStatistics();                              // Initialize the flow_IAT
        fwd_IAT = SummaryStatistics();                               // Initialize the fwd_IAT
        bwd_IAT = SummaryStatistics();                               // Initialize the bwd_IAT
        flow_active = SummaryStatistics();                           // Initialize the flow_active
        flow_idle = SummaryStatistics();                             // Initialize the flow_idle
        flow_length_stats = SummaryStatistics();                     // Initialize the flow_length_stats
        fwd_pkt_stats = SummaryStatistics();                         // Initialize the fwd_pkt_stats
        bwd_pkt_stats = SummaryStatistics();                         // Initialize the bwd_pkt_stats
        flag_counts = std::unordered_map<std::string, MutableInt>(); // Initialize the flag_counts
        init_flags();                                                // Initialize the flags
        fwd_bytes = 0L;                                              // Initialize the fwd_bytes
        bwd_bytes = 0L;                                              // Initialize the bwd_bytes
        start_active_time = 0L;                                      // Initialize the start_active_time
        end_active_time = 0L;                                        // Initialize the end_active_time
        src = "";                                                    // Initialize the src
        dst = "";                                                    // Initialize the dst
        fwd_psh_cnt = 0;                                             // Initialize the fwd_psh_cnt
        bwd_psh_cnt = 0;                                             // Initialize the bwd_psh_cnt
        fwd_urg_cnt = 0;                                             // Initialize the fwd_urg_cnt
        fwd_header_bytes = 0L;                                       // Initialize the fwd_header_bytes
        bwd_header_bytes = 0L;                                       // Initialize the bwd_header_bytes
    }
    void init_flags()
    {
        flag_counts["FIN"] = MutableInt();
        flag_counts["SYN"] = MutableInt();
        flag_counts["RST"] = MutableInt();
        flag_counts["PSH"] = MutableInt();
        flag_counts["ACK"] = MutableInt();
        flag_counts["URG"] = MutableInt();
        flag_counts["CWR"] = MutableInt();
        flag_counts["ECE"] = MutableInt();
    }

    void first_packet(BasicPacketInfo &packet)
    {
        update_flow_bulk(packet);
        detect_update_subflows(packet);
        check_flags(packet);
        uint64_t current_timestamp = packet.get_timestamp();

        if (is_bidirectional)
        {
            this->flow_length_stats.add_value(packet.get_payload_bytes());

            if (this->src == packet.get_src_ip())
            {
                if (packet.get_payload_bytes() > 0)
                {
                    this->act_data_pkt_fwd++;
                }
                this->fwd_pkt_stats.add_value((double)packet.get_payload_bytes());
                this->fwd_header_bytes += packet.get_header_bytes();
                this->forward.push_back(packet);
                this->fwd_bytes += packet.get_payload_bytes();
                if (this->forward.size() > 1)
                {
                    this->fwd_IAT.add_value(current_timestamp - this->fwd_last_seen);
                    this->fwd_last_seen = current_timestamp;
                    this->min_seg_size_fwd = std::min(this->min_seg_size_fwd, packet.get_header_bytes());
                }
            }
            else
            {
                this->bwd_pkt_stats.add_value((double)packet.get_payload_bytes());
                this->bwd_header_bytes += packet.get_header_bytes();
                this->backward.push_back(packet);
                this->bwd_bytes += packet.get_payload_bytes();
                if (this->backward.size() > 1)
                {
                    this->bwd_IAT.add_value(current_timestamp - this->bwd_last_seen);
                    this->bwd_last_seen = current_timestamp;
                }
            }
        }
        else
        {
            if (packet.get_payload_bytes() > 0)
            {
                this->act_data_pkt_fwd++;
            }
            this->fwd_pkt_stats.add_value((double)packet.get_payload_bytes());
            this->flow_length_stats.add_value((double)packet.get_payload_bytes());
            this->fwd_header_bytes += packet.get_header_bytes();
            this->forward.push_back(packet);
            this->fwd_bytes += packet.get_payload_bytes();
            this->fwd_IAT.add_value(current_timestamp - this->fwd_last_seen);
            this->fwd_last_seen = current_timestamp;
            this->min_seg_size_fwd = std::min(this->min_seg_size_fwd, packet.get_header_bytes());
        }

        this->flow_IAT.add_value(packet.get_timestamp() - this->flow_last_seen);
        this->flow_last_seen = packet.get_timestamp();
    }

    void add_packet(BasicPacketInfo &packet)
    {
        update_flow_bulk(packet);
        detect_update_subflows(packet);
        check_flags(packet);
        uint64_t current_timestamp = packet.get_timestamp();

        if (is_bidirectional)
        {
            this->flow_length_stats.add_value(packet.get_payload_bytes());

            if (this->src == packet.get_src_ip())
            {
                if (packet.get_payload_bytes() > 0)
                {
                    this->act_data_pkt_fwd++;
                }
                this->fwd_pkt_stats.add_value((double)packet.get_payload_bytes());
                this->fwd_header_bytes += packet.get_header_bytes();
                this->forward.push_back(packet);
                this->fwd_bytes += packet.get_payload_bytes();
                if (this->forward.size() > 1)
                    this->fwd_IAT.add_value(current_timestamp - this->fwd_last_seen);
                this->fwd_last_seen = current_timestamp;
                this->min_seg_size_fwd = std::min(this->min_seg_size_fwd, packet.get_header_bytes());
            }
            else
            {
                this->bwd_pkt_stats.add_value((double)packet.get_payload_bytes());
                this->init_win_bytes_bwd = packet.get_tcp_window();
                this->bwd_header_bytes += packet.get_header_bytes();
                this->backward.push_back(packet);
                this->bwd_bytes += packet.get_payload_bytes();
                if (this->backward.size() > 1)
                    this->bwd_IAT.add_value(current_timestamp - this->bwd_last_seen);
                this->bwd_last_seen = current_timestamp;
            }
        }
        else
        {
            if (packet.get_payload_bytes() > 0)
            {
                this->act_data_pkt_fwd++;
            }
            this->fwd_pkt_stats.add_value((double)packet.get_payload_bytes());
            this->flow_length_stats.add_value((double)packet.get_payload_bytes());
            this->fwd_header_bytes += packet.get_header_bytes();
            this->forward.push_back(packet);
            this->fwd_bytes += packet.get_payload_bytes();
            this->fwd_IAT.add_value(current_timestamp - this->fwd_last_seen);
            this->fwd_last_seen = current_timestamp;
            this->min_seg_size_fwd = std::min(this->min_seg_size_fwd, packet.get_header_bytes());
        }
        this->flow_IAT.add_value(packet.get_timestamp() - this->flow_last_seen);
        this->flow_last_seen = packet.get_timestamp();
    }
    double get_fwd_pkt_per_second()
    {
        uint64_t duration = this->flow_last_seen - this->flow_start_time;
        if (duration > 0)
        {
            return (this->forward.size() / ((double)duration / 1000000L));
        }
        else
        {
            return 0;
        }
    }

    double get_bwd_pkt_per_second()
    {
        uint64_t duration = this->flow_last_seen - this->flow_start_time;
        if (duration > 0)
        {
            return (this->backward.size() / ((double)duration / 1000000L));
        }
        else
        {
            return 0;
        }
    }

    double get_down_up_ratio()
    {
        if (this->forward.size() > 0)
        {
            return (double)(this->backward.size() / this->forward.size());
        }
    }

    double get_avg_pkt_size()
    {
        if (this->packet_count() > 0)
        {
            return (double)(this->flow_length_stats.get_sum() / this->packet_count());
        }
        return 0;
    }

    double get_fwd_avg_segment_size()
    {
        if (this->forward.size() > 0)
        {
            return (this->fwd_pkt_stats.get_sum() / this->forward.size());
        }
        return 0;
    }

    double get_bwd_avg_segment_size()
    {
        if (this->backward.size() > 0)
        {
            return (this->bwd_pkt_stats.get_sum() / this->backward.size());
        }
        return 0;
    }

    uint64_t packet_count()
    {
        if (is_bidirectional)
        {
            return this->forward.size() + this->backward.size();
        }
        else
        {
            return this->forward.size();
        }
    }
    void check_flags(BasicPacketInfo &packet)
    {
        if (packet.has_flag_fin())
            flag_counts["FIN"].increment();
        if (packet.has_flag_syn())
            flag_counts["SYN"].increment();
        if (packet.has_flag_rst())
            flag_counts["RST"].increment();
        if (packet.has_flag_psh())
            flag_counts["PSH"].increment();
        if (packet.has_flag_ack())
            flag_counts["ACK"].increment();
        if (packet.has_flag_urg())
            flag_counts["URG"].increment();
        if (packet.has_flag_cwr())
            flag_counts["CWR"].increment();
        if (packet.has_flag_ece())
            flag_counts["ECE"].increment();
    }

    uint64_t get_subflow_fwd_bytes()
    {
        if (this->subflow_count <= 0)
            return 0;
        return this->fwd_bytes / this->subflow_count;
    }

    uint64_t get_subflow_fwd_packets()
    {
        if (this->subflow_count <= 0)
            return 0;
        return this->forward.size() / this->subflow_count;
    }

    uint64_t get_subflow_bwd_bytes()
    {
        if (this->subflow_count <= 0)
            return 0;
        return this->bwd_bytes / this->subflow_count;
    }

    uint64_t get_subflow_bwd_packets()
    {
        if (this->subflow_count <= 0)
            return 0;
        return this->backward.size() / this->subflow_count;
    }

    void update_activate_idle_time(uint64_t current_time, uint64_t threshold)
    {
        if ((current_time - this->end_active_time) > threshold)
        {
            if ((this->end_active_time - this->start_active_time) > 0)
                this->flow_active.add_value(this->end_active_time - this->start_active_time);
            this->flow_idle.add_value(current_time - this->end_active_time);
            this->start_active_time = current_time;
            this->end_active_time = current_time;
        }
        else
        {
            this->end_active_time = current_time;
        }
    }

    void end_active_idle_time(uint64_t current_time, uint64_t threshold, uint64_t flow_timeout, bool is_flag_end)
    {
        if ((this->end_active_time - this->start_active_time) > 0)
        {
            this->flow_active.add_value(this->end_active_time - this->start_active_time);
        }

        if (!is_flag_end && ((flow_timeout - (this->end_active_time - this->flow_start_time)) > 0))
        {
            this->flow_idle.add_value(flow_timeout - (this->end_active_time - this->flow_start_time));
        }
    }

    std::string dump_flow_based_features()
    {
        std::string dump = "";
        // tuple
        dump += this->flow_id + separator;
        dump += this->src + separator;
        dump += std::to_string(src_port) + separator;
        dump += this->dst + separator;
        dump += std::to_string(dst_port) + separator;
        dump += std::to_string(protocol) + separator;
        // time
        dump += std::to_string(this->flow_start_time) + separator;
        uint64_t flow_duration = this->flow_last_seen - this->flow_start_time;
        dump += std::to_string(flow_duration) + separator;
        // fwd and bwd
        dump += std::to_string(this->fwd_pkt_stats.get_n()) + separator;
        dump += std::to_string(this->bwd_pkt_stats.get_n()) + separator;
        dump += std::to_string(this->fwd_pkt_stats.get_sum()) + separator;
        dump += std::to_string(this->bwd_pkt_stats.get_sum()) + separator;
        if (this->fwd_pkt_stats.get_n() > 0)
        {
            dump += std::to_string(this->fwd_pkt_stats.get_max()) + separator;
            dump += std::to_string(this->fwd_pkt_stats.get_min()) + separator;
            dump += std::to_string(this->fwd_pkt_stats.get_mean()) + separator;
            dump += std::to_string(this->fwd_pkt_stats.get_std()) + separator;
        }
        else
        {
            dump += "0" + separator;
            dump += "0" + separator;
            dump += "0" + separator;
            dump += "0" + separator;
        }
        if (this->bwd_pkt_stats.get_n() > 0)
        {
            dump += std::to_string(this->bwd_pkt_stats.get_max()) + separator;
            dump += std::to_string(this->bwd_pkt_stats.get_min()) + separator;
            dump += std::to_string(this->bwd_pkt_stats.get_mean()) + separator;
            dump += std::to_string(this->bwd_pkt_stats.get_std()) + separator;
        }
        else
        {
            dump += "0" + separator;
            dump += "0" + separator;
            dump += "0" + separator;
            dump += "0" + separator;
        }

        // flow duration in microseconds, therefore packet per second
        dump += std::to_string(((double)this->fwd_bytes + this->bwd_bytes) / ((double)flow_duration / 1000000L)) + separator;
        dump += std::to_string(((double)this->packet_count()) / ((double)flow_duration / 1000000L)) + separator;
        dump += std::to_string(this->flow_IAT.get_mean()) + separator;
        dump += std::to_string(this->flow_IAT.get_std()) + separator;
        dump += std::to_string(this->flow_IAT.get_max()) + separator;
        dump += std::to_string(this->flow_IAT.get_min()) + separator;
        if (this->forward.size() > 1)
        {
            dump += std::to_string(this->fwd_IAT.get_sum()) + separator;
            dump += std::to_string(this->fwd_IAT.get_mean()) + separator;
            dump += std::to_string(this->fwd_IAT.get_std()) + separator;
            dump += std::to_string(this->fwd_IAT.get_max()) + separator;
            dump += std::to_string(this->fwd_IAT.get_min()) + separator;
        }
        else
        {
            dump += "0" + separator;
            dump += "0" + separator;
            dump += "0" + separator;
            dump += "0" + separator;
            dump += "0" + separator;
        }

        if (this->backward.size() > 1)
        {
            dump += std::to_string(this->bwd_IAT.get_sum()) + separator;
            dump += std::to_string(this->bwd_IAT.get_mean()) + separator;
            dump += std::to_string(this->bwd_IAT.get_std()) + separator;
            dump += std::to_string(this->bwd_IAT.get_max()) + separator;
            dump += std::to_string(this->bwd_IAT.get_min()) + separator;
        }
        else
        {
            dump += "0" + separator;
            dump += "0" + separator;
            dump += "0" + separator;
            dump += "0" + separator;
            dump += "0" + separator;
        }

        // psh and urg
        dump += std::to_string(this->fwd_psh_cnt) + separator;
        dump += std::to_string(this->bwd_psh_cnt) + separator;
        dump += std::to_string(this->fwd_urg_cnt) + separator;
        dump += std::to_string(this->bwd_urg_cnt) + separator;

        // header bytes
        dump += std::to_string(this->fwd_header_bytes) + separator;
        dump += std::to_string(this->bwd_header_bytes) + separator;
        // packet per second
        dump += std::to_string(this->get_fwd_pkt_per_second()) + separator;
        dump += std::to_string(this->get_bwd_pkt_per_second()) + separator;

        // packet length
        if (this->forward.size() > 0 || this->forward.size() > 0)
        {
            dump += std::to_string(this->flow_length_stats.get_min()) + separator;
            dump += std::to_string(this->flow_length_stats.get_max()) + separator;
            dump += std::to_string(this->flow_length_stats.get_mean()) + separator;
            dump += std::to_string(this->flow_length_stats.get_std()) + separator;
            dump += std::to_string(this->flow_length_stats.get_variance()) + separator;
        }
        else
        {
            dump += "0" + separator;
            dump += "0" + separator;
            dump += "0" + separator;
            dump += "0" + separator;
            dump += "0" + separator;
        }

        // flags count
        for (auto &pair : flag_counts)
        {
            dump += std::to_string(pair.second.get()) + separator;
        }

        // ratio
        dump += std::to_string(this->get_down_up_ratio()) + separator;
        dump += std::to_string(this->get_avg_pkt_size()) + separator;
        dump += std::to_string(this->get_fwd_avg_segment_size()) + separator;
        dump += std::to_string(this->get_bwd_avg_segment_size()) + separator;
        dump += std::to_string(this->fwd_header_bytes) + separator; // this feature is duplicated

        dump += std::to_string(this->fwd_avg_bytes_per_bulk()) + separator;
        dump += std::to_string(this->fwd_avg_packets_per_bulk()) + separator;
        dump += std::to_string(this->fwd_avg_bulk_rate()) + separator;
        dump += std::to_string(this->fwd_avg_bytes_per_bulk()) + separator;
        dump += std::to_string(this->bwd_avg_packets_per_bulk()) + separator;
        dump += std::to_string(this->bwd_avg_bulk_rate()) + separator;

        // subflow
        dump += std::to_string(this->get_subflow_fwd_packets()) + separator;
        dump += std::to_string(this->get_subflow_fwd_bytes()) + separator;
        dump += std::to_string(this->get_subflow_bwd_packets()) + separator;
        dump += std::to_string(this->get_subflow_bwd_bytes()) + separator;

        // tcp window
        dump += std::to_string(this->init_win_bytes_fwd) + separator;
        dump += std::to_string(this->init_win_bytes_bwd) + separator;

        // act data and segment size
        dump += std::to_string(this->act_data_pkt_fwd) + separator;
        dump += std::to_string(this->min_seg_size_fwd) + separator;

        if (this->flow_active.get_n() > 0)
        {
            dump += std::to_string(this->flow_active.get_mean()) + separator;
            dump += std::to_string(this->flow_active.get_std()) + separator;
            dump += std::to_string(this->flow_active.get_max()) + separator;
            dump += std::to_string(this->flow_active.get_min()) + separator;
        }
        else
        {
            dump += "0" + separator;
            dump += "0" + separator;
            dump += "0" + separator;
            dump += "0" + separator;
        }

        if (this->flow_idle.get_n() > 0)
        {
            dump += std::to_string(this->flow_idle.get_mean()) + separator;
            dump += std::to_string(this->flow_idle.get_std()) + separator;
            dump += std::to_string(this->flow_idle.get_max()) + separator;
            dump += std::to_string(this->flow_idle.get_min()) + separator;
        }
        else
        {
            dump += "0" + separator;
            dump += "0" + separator;
            dump += "0" + separator;
            dump += "0" + separator;
        }

        dump += separator + get_label();

        return dump;
    }

    std::string get_label()
    {
        return "No Label";
    }

private:
    void update_flow_bulk(BasicPacketInfo &packet)
    {
        if (src == packet.get_src_ip())
        {
            update_fwd_bulk(packet, bwd_bulk_last_timestamp);
        }
        else
        {
            update_bwd_bulk(packet, fwd_bulk_last_timestamp);
        }
    }

    void update_fwd_bulk(BasicPacketInfo &packet, uint64_t timestamp_of_last_bulk_in_other)
    {
        uint64_t size = packet.get_payload_bytes();
        if (timestamp_of_last_bulk_in_other > fwd_bulk_start_helper)
            fwd_bulk_start_helper = 0;
        if (size <= 0)
            return;

        packet.get_payload_packets();

        if (fwd_bulk_start_helper == 0)
        {
            fwd_bulk_start_helper = packet.get_timestamp();
            fwd_bulk_packet_count_helper = 1;
            fwd_bulk_size_helper = size;
            fwd_bulk_last_timestamp = packet.get_timestamp();
        } // possible bulk
        else
        {
            // Too much idle time?
            if (((packet.get_timestamp() - fwd_bulk_last_timestamp) / (double)1000000 > 1.0))
            {
                fwd_bulk_start_helper = packet.get_timestamp();
                fwd_bulk_last_timestamp = packet.get_timestamp();
                fwd_bulk_packet_count_helper = 1;
                fwd_bulk_size_helper = size;
            }
            else
            {
                fwd_bulk_packet_count_helper++;
                fwd_bulk_size_helper += size;
                // new bulk
                if (fwd_bulk_packet_count_helper == 4)
                {
                    fwd_bulk_state_count++;
                    fwd_bulk_packet_count += fwd_bulk_packet_count_helper;
                    fwd_bulk_size_total += fwd_bulk_size_helper;
                    fwd_bulk_duration += packet.get_timestamp() - fwd_bulk_start_helper;
                }
                else if (fwd_bulk_packet_count_helper > 4)
                {
                    fwd_bulk_packet_count += 1;
                    fwd_bulk_size_total += size;
                    fwd_bulk_duration += packet.get_timestamp() - fwd_bulk_last_timestamp;
                }
                fwd_bulk_last_timestamp = packet.get_timestamp();
            }
        }
    }

    void update_bwd_bulk(BasicPacketInfo &packet, uint64_t timestamp_of_last_bulk_in_other)
    {
        uint64_t size = packet.get_payload_bytes();
        if (timestamp_of_last_bulk_in_other > bwd_bulk_start_helper)
            bwd_bulk_start_helper = 0;
        if (size <= 0)
            return;

        packet.get_payload_packets();

        if (bwd_bulk_start_helper == 0)
        {
            bwd_bulk_start_helper = packet.get_timestamp();
            bwd_bulk_packet_count_helper = 1;
            bwd_bulk_size_helper = size;
            bwd_bulk_last_timestamp = packet.get_timestamp();
        } // possible bulk
        else
        {
            // Too much idle time?
            if (((packet.get_timestamp() - bwd_bulk_last_timestamp) / (double)1000000 > 1.0))
            {
                bwd_bulk_start_helper = packet.get_timestamp();
                bwd_bulk_last_timestamp = packet.get_timestamp();
                bwd_bulk_packet_count_helper = 1;
                bwd_bulk_size_helper = size;
            }
            else
            {
                bwd_bulk_packet_count_helper++;
                bwd_bulk_size_helper += size;
                // new bulk
                if (bwd_bulk_packet_count_helper == 4)
                {
                    bwd_bulk_state_count++;
                    bwd_bulk_packet_count += bwd_bulk_packet_count_helper;
                    bwd_bulk_size_total += bwd_bulk_size_helper;
                    bwd_bulk_duration += packet.get_timestamp() - bwd_bulk_start_helper;
                }
                else if (bwd_bulk_packet_count_helper > 4)
                {
                    bwd_bulk_packet_count += 1;
                    bwd_bulk_size_total += size;
                    bwd_bulk_duration += packet.get_timestamp() - bwd_bulk_last_timestamp;
                }
                bwd_bulk_last_timestamp = packet.get_timestamp();
            }
        }
    }

    void detect_update_subflows(BasicPacketInfo &packet)
    {
        if (subflow_last_packet_timestamp == -1)
        {
            subflow_last_packet_timestamp = packet.get_timestamp();
            subflow_ac_helper = packet.get_payload_bytes();
        }

        if (((packet.get_timestamp() - subflow_last_packet_timestamp) / (double)1000000) > 1.0)
        {
            subflow_count++;
            uint64_t last_subflow_duration = packet.get_timestamp() - subflow_ac_helper;
            update_activate_idle_time(packet.get_timestamp() - subflow_last_packet_timestamp, 5000000L);
            subflow_ac_helper = packet.get_timestamp();
        }
        subflow_last_packet_timestamp = packet.get_timestamp();
    }

    uint64_t fwd_bulk_state_count()
    {
        return fwd_bulk_state_count;
    }

    uint64_t fwd_bulk_size_total()
    {
        return fwd_bulk_size_total;
    }

    uint64_t fwd_bulk_packet_count()
    {
        return fwd_bulk_packet_count;
    }

    uint64_t fwd_bulk_duration()
    {
        return fwd_bulk_duration;
    }

    double fwd_bulk_duration_in_second()
    {
        return fwd_bulk_duration / (double)1000000;
    }

    // client average bytes per bulk
    uint64_t fwd_avg_bytes_per_bulk()
    {
        if (this->fwd_bulk_state_count != 0)
            return this->fwd_bulk_size_total / this->fwd_bulk_state_count;
        return 0;
    }

    // client average packets per bulk
    uint64_t fwd_avg_packets_per_bulk()
    {
        if (this->fwd_bulk_state_count != 0)
            return this->fwd_bulk_packet_count / this->fwd_bulk_state_count;
        return 0;
    }

    // client average bulk rate
    uint64_t fwd_avg_bulk_rate()
    {
        if (this->fwd_bulk_duration != 0)
            return (uint64_t)(this->fwd_bulk_size_total / this->fwd_bulk_duration_in_second());
        return 0;
    }

    // new features server
    uint64_t bwd_bulk_packet_count()
    {
        return bwd_bulk_packet_count;
    }

    uint64_t bwd_bulk_state_count()
    {
        return bwd_bulk_state_count;
    }

    uint64_t bwd_bulk_size_total()
    {
        return bwd_bulk_size_total;
    }

    uint64_t bwd_bulk_duration()
    {
        return bwd_bulk_duration;
    }

    double bwd_bulk_duration_in_second()
    {
        return bwd_bulk_duration / (double)1000000;
    }

    // server average bytes per bulk
    uint64_t bwd_avg_bytes_per_bulk()
    {
        if (this->bwd_bulk_state_count != 0)
            return this->bwd_bulk_size_total / this->bwd_bulk_state_count;
        return 0;
    }

    // server average packets per bulk
    uint64_t bwd_avg_packets_per_bulk()
    {
        if (this->bwd_bulk_state_count != 0)
            return this->bwd_bulk_packet_count / this->bwd_bulk_state_count;
        return 0;
    }

    // server average bulk rate
    uint64_t bwd_avg_bulk_rate()
    {
        if (this->bwd_bulk_duration != 0)
            return (uint64_t)(this->bwd_bulk_size_total / this->bwd_bulk_duration_in_second());
        return 0;
    }
};
#endif // BASIC_FLOW_H