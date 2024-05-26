#ifndef _BASIC_PACKET_INFO_H_
#define _BASIC_PACKET_INFO_H_

#include <string>
#include <cstdint>
#include "id_generator.h"

// Basic Packet information
class BasicPacketInfo
{
private:
    uint64_t id;
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint64_t timestamp;
    uint64_t payload_bytes = 0;
    std::string flow_id;
    bool flag_fin = false;
    bool flag_psh = false;
    bool flag_urg = false;
    bool flag_ece = false;
    bool flag_syn = false;
    bool flag_ack = false;
    bool flag_cwr = false;
    bool flag_rst = false;
    uint64_t tcp_window = 0;
    uint64_t header_bytes = 0;
    uint64_t payload_packets = 0;

public:
    BasicPacketInfo(std::string src_ip, std::string dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t protocol, uint64_t timestamp)
        : src_ip(std::move(src_ip)), dst_ip(std::move(dst_ip)), src_port(src_port), dst_port(dst_port), protocol(protocol), timestamp(timestamp)
    {
        this->id = next_id();
        generate_flow_id();
    }

    std::string generate_flow_id()
    {
        bool forward = src_ip < dst_ip;

        if (forward)
            this->flow_id = src_ip + "-" + dst_ip + "-" + std::to_string(src_port) + "-" + std::to_string(dst_port) + "-" + std::to_string(protocol);
        else
            this->flow_id = dst_ip + "-" + src_ip + "-" + std::to_string(dst_port) + "-" + std::to_string(src_port) + "-" + std::to_string(protocol);
        return this->flow_id;
    }

    std::string fwd_flow_id()
    {
        this->flow_id = src_ip + "-" + dst_ip + "-" + std::to_string(src_port) + "-" + std::to_string(dst_port) + "-" + std::to_string(protocol);
        return this->flow_id;
    }

    std::string bwd_flow_id()
    {
        this->flow_id = dst_ip + "-" + src_ip + "-" + std::to_string(dst_port) + "-" + std::to_string(src_port) + "-" + std::to_string(protocol);
        return this->flow_id;
    }

    uint64_t get_id() const
    {
        return id;
    }

    void set_id(uint64_t id)
    {
        this->id = id;
    }

    std::string get_src_ip() const
    {
        return src_ip;
    }

    void set_src_ip(std::string src_ip)
    {
        this->src_ip = src_ip;
    }

    std::string get_dst_ip() const
    {
        return dst_ip;
    }

    void set_dst_ip(std::string dst_ip)
    {
        this->dst_ip = dst_ip;
    }

    uint16_t get_src_port() const
    {
        return src_port;
    }

    void set_src_port(uint16_t src_port)
    {
        this->src_port = src_port;
    }

    uint16_t get_dst_port() const
    {
        return dst_port;
    }

    void set_dst_port(uint16_t dst_port)
    {
        this->dst_port = dst_port;
    }

    uint8_t get_protocol() const
    {
        return protocol;
    }

    void set_protocol(uint8_t protocol)
    {
        this->protocol = protocol;
    }

    uint64_t get_timestamp() const
    {
        return timestamp;
    }

    void set_timestamp(uint64_t timestamp)
    {
        this->timestamp = timestamp;
    }

    uint64_t get_payload_bytes() const
    {
        return payload_bytes;
    }

    void set_payload_bytes(uint64_t payload_bytes)
    {
        this->payload_bytes = payload_bytes;
    }

    uint64_t get_header_bytes() const
    {
        return header_bytes;
    }

    void set_header_bytes(uint64_t header_bytes)
    {
        this->header_bytes = header_bytes;
    }

    bool has_flag_fin() const
    {
        return flag_fin;
    }

    void set_flag_fin(bool flag_fin)
    {
        this->flag_fin = flag_fin;
    }

    bool has_flag_psh() const
    {
        return flag_psh;
    }

    void set_flag_psh(bool flag_psh)
    {
        this->flag_psh = flag_psh;
    }

    bool has_flag_urg() const
    {
        return flag_urg;
    }

    void set_flag_urg(bool flag_urg)
    {
        this->flag_urg = flag_urg;
    }

    bool has_flag_ece() const
    {
        return flag_ece;
    }

    void set_flag_ece(bool flag_ece)
    {
        this->flag_ece = flag_ece;
    }

    bool has_flag_syn() const
    {
        return flag_syn;
    }

    void set_flag_syn(bool flag_syn)
    {
        this->flag_syn = flag_syn;
    }

    bool has_flag_ack() const
    {
        return flag_ack;
    }

    void set_flag_ack(bool flag_ack)
    {
        this->flag_ack = flag_ack;
    }

    bool has_flag_cwr() const
    {
        return flag_cwr;
    }

    void set_flag_cwr(bool flag_cwr)
    {
        this->flag_cwr = flag_cwr;
    }

    bool has_flag_rst() const
    {
        return flag_rst;
    }

    void set_flag_rst(bool flag_rst)
    {
        this->flag_rst = flag_rst;
    }

    uint64_t get_tcp_window() const
    {
        return tcp_window;
    }

    void set_tcp_window(uint64_t tcp_window)
    {
        this->tcp_window = tcp_window;
    }
};

#endif // _BASIC_PACKET_INFO_H_
