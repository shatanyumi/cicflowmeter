#ifndef PACKET_READER_H
#define PACKET_READER_H

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <cstdio>
#include <cstring>
#include <vector>
#include <cassert>
#include <string>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include "packet.h"

// TCP flags add
#define TH_ECE 0x40
#define TH_CWR 0x80

class PacketReader
{
private:
    pcap_t *pcap_reader;

    uint64_t first_packet;
    uint64_t last_packet;

    const u_char *pkt_data;
    const struct ether_header *eth_hdr;

    const struct ip *ipv4_hdr;
    const struct ip6_hdr *ipv6_hdr;
    const struct tcphdr *tcp_hdr;
    const struct udphdr *udp_hdr;

    bool read_ipv6;
    bool read_ipv4;

    std::string file;

public:
    PacketReader(const std::string &filename, bool read_ipv4 = true, bool read_ipv6 = false)
        : read_ipv4(read_ipv4), read_ipv6(read_ipv6), pcap_reader(nullptr), first_packet(0), last_packet(0), pkt_data(nullptr),
          eth_hdr(nullptr), ipv4_hdr(nullptr), ipv6_hdr(nullptr), tcp_hdr(nullptr), udp_hdr(nullptr)
    {
        config(filename);
    }

    ~PacketReader()
    {
        if (pcap_reader)
        {
            pcap_close(pcap_reader);
        }
    }

    void config(const std::string &filename)
    {
        file = filename;
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_reader = pcap_open_offline(filename.c_str(), errbuf);
        if (pcap_reader == nullptr)
        {
            throw std::runtime_error("Error reading pcap file: " + std::string(errbuf));
        }

        first_packet = 0L;
        last_packet = 0L;
    }

    Packet *next_packet()
    {
        Packet *pkt_info = nullptr;
        try
        {
            struct pcap_pkthdr pkt_hdr;
            pkt_data = pcap_next(pcap_reader, &pkt_hdr);
            if (pkt_data == nullptr)
            {
                return pkt_info;
            }

            pkt_info = new Packet();
            eth_hdr = reinterpret_cast<const struct ether_header *>(pkt_data);
            if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP)
            {
                read_ipv4 = true;
                get_ipv4_info(*pkt_info, pkt_data, pkt_hdr);
            }
            else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IPV6)
            {
                read_ipv6 = true;
                get_ipv6_info(*pkt_info, pkt_data, pkt_hdr);
            }
        }
        catch (const std::exception &e)
        {
            std::cerr << e.what() << '\n';
            delete pkt_info;
            pkt_info = nullptr;
        }

        return pkt_info;
    }

    void get_ipv4_info(Packet &pkt_info, const u_char *pkt_data, const pcap_pkthdr &pkt_hdr)
    {
        ipv4_hdr = reinterpret_cast<const struct ip *>(pkt_data + sizeof(struct ether_header));

        pkt_info.set_src_ip(ipToString(ipv4_hdr->ip_src.s_addr));
        pkt_info.set_dst_ip(ipToString(ipv4_hdr->ip_dst.s_addr));
        pkt_info.set_protocol(ipv4_hdr->ip_p);

        update_packet_timestamps(pkt_hdr);

        if (ipv4_hdr->ip_p == IPPROTO_TCP)
        {
            tcp_hdr = reinterpret_cast<const struct tcphdr *>(pkt_data + sizeof(struct ether_header) + ipv4_hdr->ip_hl * 4);
            set_tcp_info(pkt_info, pkt_data, ipv4_hdr->ip_hl * 4);
        }
        else if (ipv4_hdr->ip_p == IPPROTO_UDP)
        {
            udp_hdr = reinterpret_cast<const struct udphdr *>(pkt_data + sizeof(struct ether_header) + ipv4_hdr->ip_hl * 4);
            set_udp_info(pkt_info, ipv4_hdr->ip_len);
        }
    }

    void get_ipv6_info(Packet &pkt_info, const u_char *pkt_data, const pcap_pkthdr &pkt_hdr)
    {
        ipv6_hdr = reinterpret_cast<const struct ip6_hdr *>(pkt_data + sizeof(struct ether_header));

        char src_ip[INET6_ADDRSTRLEN];
        char dst_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ipv6_hdr->ip6_src, src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ipv6_hdr->ip6_dst, dst_ip, INET6_ADDRSTRLEN);

        pkt_info.set_src_ip(src_ip);
        pkt_info.set_dst_ip(dst_ip);
        pkt_info.set_protocol(ipv6_hdr->ip6_nxt);

        update_packet_timestamps(pkt_hdr);

        if (ipv6_hdr->ip6_nxt == IPPROTO_TCP)
        {
            tcp_hdr = reinterpret_cast<const struct tcphdr *>(pkt_data + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
            set_tcp_info(pkt_info, pkt_data, sizeof(struct ip6_hdr));
        }
        else if (ipv6_hdr->ip6_nxt == IPPROTO_UDP)
        {
            udp_hdr = reinterpret_cast<const struct udphdr *>(pkt_data + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
            set_udp_info(pkt_info, ipv6_hdr->ip6_plen);
        }
    }

    void update_packet_timestamps(const pcap_pkthdr &pkt_hdr)
    {
        if (first_packet == 0)
        {
            first_packet = pkt_hdr.ts.tv_sec * 1000000 + pkt_hdr.ts.tv_usec;
        }
        last_packet = pkt_hdr.ts.tv_sec * 1000000 + pkt_hdr.ts.tv_usec;
    }

    void set_tcp_info(Packet &pkt_info, const u_char *pkt_data, uint16_t ip_header_length)
    {
        pkt_info.set_tcp_window(ntohs(tcp_hdr->th_win));
        pkt_info.set_src_port(ntohs(tcp_hdr->th_sport));
        pkt_info.set_dst_port(ntohs(tcp_hdr->th_dport));
        pkt_info.set_flag_fin(tcp_hdr->th_flags & TH_FIN);
        pkt_info.set_flag_psh(tcp_hdr->th_flags & TH_PUSH);
        pkt_info.set_flag_urg(tcp_hdr->th_flags & TH_URG);
        pkt_info.set_flag_syn(tcp_hdr->th_flags & TH_SYN);
        pkt_info.set_flag_ack(tcp_hdr->th_flags & TH_ACK);
        pkt_info.set_flag_ece(tcp_hdr->th_flags & TH_ECE);
        pkt_info.set_flag_cwr(tcp_hdr->th_flags & TH_CWR);
        pkt_info.set_payload_bytes(ntohs(ipv4_hdr->ip_len) - ip_header_length - tcp_hdr->th_off * 4);
        pkt_info.set_header_bytes(sizeof(struct ether_header) + ip_header_length + tcp_hdr->th_off * 4);
    }

    void set_udp_info(Packet &pkt_info, uint16_t ip_payload_length)
    {
        pkt_info.set_src_port(ntohs(udp_hdr->uh_sport));
        pkt_info.set_dst_port(ntohs(udp_hdr->uh_dport));
        pkt_info.set_payload_bytes(ntohs(udp_hdr->uh_ulen) - sizeof(struct udphdr));
        pkt_info.set_header_bytes(sizeof(struct ether_header) + ip_payload_length + sizeof(struct udphdr));
    }

    inline uint32_t ipToLong(const std::string &ip)
    {
        std::istringstream ss(ip);
        uint32_t result = 0;
        uint32_t cur = 0;
        uint32_t cnt = 0;
        std::string segment;

        while (std::getline(ss, segment, '.'))
        {
            if (cnt >= 4)
            {
                throw std::invalid_argument("Invalid IP address");
            }
            cur = std::stoul(segment);
            if (cur > 255)
            {
                throw std::invalid_argument("Invalid IP address segment");
            }
            result = (result << 8) + cur;
            ++cnt;
        }
        if (cnt != 4)
        {
            throw std::invalid_argument("Invalid IP address");
        }
        return result;
    }

    inline std::string ipToString(uint32_t ip)
    {
        using std::to_string;
        return to_string(ip >> 24) + "." + to_string((ip >> 16) & 255) + "." + to_string((ip >> 8) & 255) + "." + to_string(ip & 255);
    }
};

#endif // PACKET_READER_H
