// packet reader
#ifndef PACKET_READER_H
#define PACKET_READER_H

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <string>
#include "id_generator.h"
#include "basic_packet_info.h"
#include <iostream>

class PacketReader
{

private:
    IDGenerator id_generator;
    pcap_t *pcap_reader;

    uint64_t first_packet;
    uint64_t last_packet;

    struct pcap_pkthdr *pkt_hdr;
    const u_char *pkt_data;
    const struct ether_header *eth_hdr;

    const struct ip *ip_hdr;
    const struct ip6_hdr *ip6_hdr;
    const struct l2tp_hdr *l2tp_hdr;

    const struct tcphdr *tcp_hdr;
    const struct udphdr *udp_hdr;

    bool read_ipv6;
    bool read_ipv4;

    std::string file;

public:
    PacketReader(std::string filename){
        this->read_ipv4 = true;
        this->read_ipv6 = false;
        config(filename);
    }

    PacketReader(std::string filename, bool read_ipv4, bool read_ipv6){
        this->read_ipv4 = read_ipv4;
        this->read_ipv6 = read_ipv6;
        config(filename);
    }

    void config(std::string filename){
        this->file = filename;
        char errbuf[PCAP_ERRBUF_SIZE];
        this->pcap_reader = pcap_open_offline(filename.c_str(), errbuf);
        if (this->pcap_reader == NULL)
        {
            fprintf(stderr, "Error reading pcap file: %s\n", errbuf);
            exit(1);
        }

        this->first_packet = 0L;
        this->last_packet = 0L;

        this->pkt_hdr = new struct pcap_pkthdr;
    }

    BasicPacketInfo* next_packet(){
        BasicPacketInfo *pkt_info;

        try
        {
            this->pkt_data = pcap_next(this->pcap_reader, this->pkt_hdr);
            if(this->pkt_data == NULL){
                return nullptr;
            }
        }
        catch(const std::exception& e)
        {
            std::cerr << e.what() << '\n';
        }
        
        return pkt_info;
    }
};

#endif // PACKET_READER_H