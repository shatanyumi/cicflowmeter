#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <vector>
#include <cassert>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <iostream>
#include <cmath>

using namespace std;

#define debug(x) std::cerr << #x << " = " << x
#define sp << " "
#define ln << "\n"

// feat adaptor for data analysis
struct feat_adaptor
{
    uint64_t _min, _max, _count, _last, _x_sum, _x2_sum;
    feat_adaptor() { _min = UINT32_MAX, _max = _count = _x_sum = _x2_sum = _last = 0; }
    inline void append(uint64_t x) { _min = std::min(_min, x), _max = std::max(_max, x), _count += 1, _x_sum += x, _x2_sum += x * x, _last = x; }
    inline uint64_t min() const { return _min; }
    inline uint64_t max() const { return _max; }
    inline uint64_t sum() const { return _x_sum; }
    inline uint64_t avg() const { return _count > 0 ? _x_sum / _count : 0ull; }
    inline double std() const { return _count > 0 ? sqrt(static_cast<double>(_x2_sum) / _count - static_cast<double>(avg()) * avg()) : 0.0; }
    inline uint64_t count() const { return _count; }
    inline uint64_t last() const { return _last; }
};

// flow stats struct, store all states of flows
struct FlowStats
{
    feat_adaptor fwd_pkt_len;
    feat_adaptor fwd_ipd;
    feat_adaptor fwd_ts;
    uint64_t start_ts, end_ts;
    uint64_t fwd_pkt_count;
    uint64_t fwd_header_len;
    uint64_t init_win_bytes_forward;
    uint64_t act_data_pkt_fwd, min_seg_size_forward;
    uint64_t fin_cnt, syn_cnt, rst_cnt, psh_cnt, ack_cnt, urg_cnt, cwe_cnt, ece_cnt;

    FlowStats() : start_ts(0), end_ts(0), fwd_pkt_count(0), fwd_header_len(0), init_win_bytes_forward(0), act_data_pkt_fwd(0), min_seg_size_forward(0),
                  fin_cnt(0), syn_cnt(0), rst_cnt(0), psh_cnt(0), ack_cnt(0), urg_cnt(0), cwe_cnt(0), ece_cnt(0) {}
};

inline uint32_t ip2long(const char *ip)
{
    uint32_t result = 0, cur = 0, cnt = 0;
    for (size_t i = 0, n = strlen(ip); i < n; i += 1)
    {
        if (ip[i] == '.')
            result = (result << 8) + cur, cur = 0, cnt += 1;
        else
            cur = cur * 10u + (uint32_t)(ip[i] - '0');
        assert(cur <= 255), assert(cnt <= 3);
    }
    return assert(cnt == 3), (result << 8) + cur;
}

inline void ip2string(uint32_t ip, char *result)
{
    sprintf(result, "%u.%u.%u.%u", ip >> 24, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255);
}
inline std::string ip2string(uint32_t ip)
{
    using std::__cxx11::to_string;
    return to_string(ip >> 24) + "." + to_string((ip >> 16) & 255) + "." + to_string((ip >> 8) & 255) + "." + to_string(ip & 255);
}

std::unordered_map<std::string, FlowStats> flow_stats; // all flow stats map
std::unordered_set<std::string> benigns;               // benigns labels

int main(int argc, char **argv)
{
    assert(argc >= 3);
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *cap = pcap_open_offline(argv[1], errbuf);
    if (cap == nullptr)
        fprintf(stderr, "error reading pcap file: %s\n", errbuf), exit(1);

    FILE *csv = std::fopen(argv[2], "w");
    if (csv == nullptr)
        fprintf(stderr, "error opening csv file: %s\n", argv[2]), exit(1);

    FILE *benign = nullptr;
    bool has_label = (argc >= 4);
    std::printf("processing (pcap file: %s, label file: %s) -> (csv file: %s)...\n", argv[1], has_label ? argv[3] : "none", argv[2]);

    if (has_label)
    {
        int flow_cnt;
        benign = fopen(argv[3], "r");
        assert(fscanf(benign, "%d", &flow_cnt) != EOF);
        char flow_id[100];
        while (std::fscanf(benign, "%s", flow_id) != EOF)
            benigns.insert(std::string(flow_id));
    }

    const char csv_header[] = "Flow ID,Source IP,Source Port,Destination IP,Destination Port,Protocol,"
                              "Flow Duration,Total Fwd Packets,Total Bwd Packets,"
                              "Total Length of Fwd Packets,Total Length of Bwd Packets,"
                              "Fwd Packet Length Max,Fwd Packet Length Min,Fwd Packet Length Mean,Fwd Packet Length Std,"
                              "Bwd Packet Length Max,Bwd Packet Length Min,Bwd Packet Length Mean,Bwd Packet Length Std,"
                              "Flow Bytes/s,Flow Packets/s,"
                              "Fwd IAT Total,Fwd IAT Mean,Fwd IAT Std,Fwd IAT Max,Fwd IAT Min,"
                              "Bwd IAT Total,Bwd IAT Mean,Bwd IAT Std,Bwd IAT Max,Bwd IAT Min,"
                              "Fwd Header Length,Bwd Header Length,"
                              "Fwd Packets/s,Bwd Packets/s,"
                              "Min Packet Length,Max Packet Length,Packet Length Mean,Packet Length Std,Packet Length Variance,"
                              "FIN Flag Count,SYN Flag Count,RST Flag Count,PSH Flag Count,ACK Flag Count,URG Flag Count,CWE Flag Count,ECE Flag Count,"
                              "Down/Up Ratio,Average Packet Size,Fwd Segment Size Avg,Bwd Segment Size Avg,"
                              "Fwd Bytes/Bulk Avg,Fwd Packet/Bulk Avg,Fwd Bulk Rate Avg,"
                              "Bwd Bytes/Bulk Avg,Bwd Packet/Bulk Avg,Bwd Bulk Rate Avg,"
                              "Subflow Fwd Packets,Subflow Fwd Bytes,Subflow Bwd Packets,Subflow Bwd Bytes,"
                              "Init_Win_bytes_forward,Init_Win_bytes_backward,act_data_pkt_fwd,min_seg_size_forward,"
                              "Active Mean,Active Std,Active Max,Active Min,"
                              "Idle Mean,Idle Std,Idle Max,Idle Min,Label\n";

    std::fprintf(csv, csv_header);

    struct pcap_pkthdr *pkt_hdr = new struct pcap_pkthdr;
    while (true)
    {
        static int iter = 0;
        iter += 1;
        const u_char *pkt_data = pcap_next(cap, pkt_hdr);
        if (pkt_data == nullptr)
            break;

        const struct ether_header *eth_hdr = reinterpret_cast<const struct ether_header *>(pkt_data);
        if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP)
            continue;

        const struct ip *ip_hdr = reinterpret_cast<const struct ip *>(pkt_data + sizeof(*eth_hdr));
        if (ip_hdr->ip_p != IPPROTO_TCP && ip_hdr->ip_p != IPPROTO_UDP)
            continue;

        uint32_t src_ip = ntohl(ip_hdr->ip_src.s_addr), dst_ip = ntohl(ip_hdr->ip_dst.s_addr);
        uint16_t src_port = 0, dst_port = 0;
        uint8_t protocol = ip_hdr->ip_p;

        const struct tcphdr *tcp_hdr = nullptr;
        const struct udphdr *udp_hdr = nullptr;
        if (protocol == IPPROTO_TCP)
        {
            tcp_hdr = reinterpret_cast<const struct tcphdr *>(pkt_data + sizeof(*eth_hdr) + sizeof(*ip_hdr));
            src_port = ntohs(tcp_hdr->th_sport), dst_port = ntohs(tcp_hdr->th_dport);
        }
        else if (protocol == IPPROTO_UDP)
        {
            udp_hdr = reinterpret_cast<const struct udphdr *>(pkt_data + sizeof(*eth_hdr) + sizeof(*ip_hdr));
            src_port = ntohs(udp_hdr->uh_sport), dst_port = ntohs(udp_hdr->uh_dport);
        }

        std::string flow_id = ip2string(src_ip) + "-" + ip2string(dst_ip) + "-" + std::to_string(src_port) + "-" + std::to_string(dst_port) + "-" + std::to_string(protocol);
        std::string reverse_flow_id = ip2string(dst_ip) + "-" + ip2string(src_ip) + "-" + std::to_string(dst_port) + "-" + std::to_string(src_port) + "-" + std::to_string(protocol);

        // if flow_id not in flow_stats, create a new flow_stats of flow_id and reverse_flow_id
        // else, update the flow_stats of flow_id and reverse_flow_id
        // note: they must be in pairs
        if (flow_stats.find(flow_id) == flow_stats.end())
        {
            flow_stats[flow_id] = FlowStats();
            flow_stats[reverse_flow_id] = FlowStats();
        }

        FlowStats &stats = flow_stats[flow_id];
        FlowStats &reverse_stats = flow_stats[reverse_flow_id];

        uint64_t timestamp = pkt_hdr->ts.tv_sec * 1000000 + pkt_hdr->ts.tv_usec;
        if (stats.start_ts == 0)
            stats.start_ts = timestamp;
        stats.end_ts = timestamp;

        uint16_t len = ntohs(ip_hdr->ip_len);

        // forward flow record
        stats.fwd_pkt_len.append(len);
        stats.fwd_pkt_count++;
        stats.fwd_ts.append(timestamp);
        if (stats.fwd_ts.count() > 1)
        {
            stats.fwd_ipd.append(stats.fwd_ts.last() - stats.fwd_ts.min());
        }

        if (protocol == IPPROTO_TCP)
        {
            stats.fwd_header_len += tcp_hdr->th_off * 4;
            if (stats.init_win_bytes_forward == 0)
                stats.init_win_bytes_forward = ntohs(tcp_hdr->th_win);
            if (tcp_hdr->th_flags & TH_FIN)
                stats.fin_cnt++;
            if (tcp_hdr->th_flags & TH_SYN)
                stats.syn_cnt++;
            if (tcp_hdr->th_flags & TH_RST)
                stats.rst_cnt++;
            if (tcp_hdr->th_flags & TH_PUSH)
                stats.psh_cnt++;
            if (tcp_hdr->th_flags & TH_ACK)
                stats.ack_cnt++;
            if (tcp_hdr->th_flags & TH_URG)
                stats.urg_cnt++;
        }
        else if (protocol == IPPROTO_UDP)
        {
            stats.fwd_header_len += 8;
            stats.init_win_bytes_forward = 0;
        }

        reverse_stats.fwd_pkt_len.append(len);
        reverse_stats.fwd_pkt_count++;
        reverse_stats.fwd_ts.append(timestamp);
        if (reverse_stats.fwd_ts.count() > 1)
        {
            reverse_stats.fwd_ipd.append(reverse_stats.fwd_ts.last() - reverse_stats.fwd_ts.min());
        }
        if (protocol == IPPROTO_TCP)
        {
            reverse_stats.fwd_header_len += tcp_hdr->th_off * 4;
            if (reverse_stats.init_win_bytes_forward == 0)
                reverse_stats.init_win_bytes_forward = ntohs(tcp_hdr->th_win);
            if (tcp_hdr->th_flags & TH_FIN)
                reverse_stats.fin_cnt++;
            if (tcp_hdr->th_flags & TH_SYN)
                reverse_stats.syn_cnt++;
            if (tcp_hdr->th_flags & TH_RST)
                reverse_stats.rst_cnt++;
            if (tcp_hdr->th_flags & TH_PUSH)
                reverse_stats.psh_cnt++;
            if (tcp_hdr->th_flags & TH_ACK)
                reverse_stats.ack_cnt++;
            if (tcp_hdr->th_flags & TH_URG)
                reverse_stats.urg_cnt++;
        }
        else if (protocol == IPPROTO_UDP)
        {
            reverse_stats.fwd_header_len += 8;
            reverse_stats.init_win_bytes_forward = 0;
        }

        double flow_duration = stats.end_ts - stats.start_ts;

        std::fprintf(csv,
                     "%s,%s,%u,%s,%u,%u,%f,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%f,%lu,%ld,%lu,%f,%f,%f,%ld,%ld,%lf,%lu,%ld,%ld,%ld,%f,%ld,%lu,%lu,%lu,%f,%f,%ld,%ld,%lu,%f,%lf,%ld,%lu,%lu,%lu,%lu,%lu,%lu,%ld,%f,%f,%ld,%ld,%f,%f,%f,%f,%f,%f,%ld,%ld,%ld,%lu,%lu,%lu,%lu,%lu,%lu,%lf,%ld,%ld,%ld,%f,%ld,%ld,%s\n",
                     flow_id.c_str(), ip2string(src_ip).c_str(), (uint32_t)src_port, ip2string(dst_ip).c_str(), (uint32_t)dst_port, (uint32_t)protocol,
                     flow_duration,
                     stats.fwd_pkt_count, reverse_stats.fwd_pkt_count,
                     stats.fwd_pkt_len.sum(), reverse_stats.fwd_pkt_len.sum(),
                     stats.fwd_pkt_len.max(), stats.fwd_pkt_len.min(), stats.fwd_pkt_len.avg(), stats.fwd_pkt_len.std(),
                     reverse_stats.fwd_pkt_len.max(), reverse_stats.fwd_pkt_len.min(), reverse_stats.fwd_pkt_len.avg(), reverse_stats.fwd_pkt_len.std(),
                     flow_duration > 0 ? (stats.fwd_pkt_len.sum() / flow_duration) : 0.0,
                     flow_duration > 0 ? (stats.fwd_pkt_count / flow_duration) : 0.0,
                     stats.fwd_ipd.sum(), stats.fwd_ipd.avg(), stats.fwd_ipd.std(), stats.fwd_ipd.max(), stats.fwd_ipd.min(),
                     reverse_stats.fwd_ipd.sum(), reverse_stats.fwd_ipd.avg(), reverse_stats.fwd_ipd.std(), reverse_stats.fwd_ipd.max(), reverse_stats.fwd_ipd.min(),
                     stats.fwd_header_len, reverse_stats.fwd_header_len,
                     flow_duration > 0 ? (stats.fwd_pkt_count / flow_duration) : 0.0,
                     flow_duration > 0 ? (reverse_stats.fwd_pkt_count / flow_duration) : 0.0,
                     stats.fwd_pkt_len.min(), stats.fwd_pkt_len.max(), stats.fwd_pkt_len.avg(), stats.fwd_pkt_len.std(),
                     static_cast<double>(stats.fwd_pkt_len.std() - stats.fwd_pkt_len.avg() * stats.fwd_pkt_len.avg()),
                     stats.fin_cnt, stats.syn_cnt, stats.rst_cnt, stats.psh_cnt, stats.ack_cnt, stats.urg_cnt, stats.cwe_cnt, stats.ece_cnt,
                     reverse_stats.fwd_pkt_len.sum() > 0 ? (static_cast<double>(stats.fwd_pkt_len.sum()) / reverse_stats.fwd_pkt_len.sum()) : 0.0,
                     (stats.fwd_pkt_count + reverse_stats.fwd_pkt_count) > 0 ? (static_cast<double>(stats.fwd_pkt_len.sum() + reverse_stats.fwd_pkt_len.sum()) / (stats.fwd_pkt_count + reverse_stats.fwd_pkt_count)) : 0.0,
                     stats.fwd_pkt_len.avg(), reverse_stats.fwd_pkt_len.avg(),
                     stats.fwd_pkt_count > 0 ? (static_cast<double>(stats.fwd_pkt_len.sum()) / stats.fwd_pkt_count) : 0.0,
                     stats.fwd_pkt_count > 0 ? (static_cast<double>(stats.fwd_pkt_count) / stats.fwd_pkt_count) : 0.0,
                     flow_duration > 0 ? (static_cast<double>(stats.fwd_pkt_count) / flow_duration) : 0.0,
                     reverse_stats.fwd_pkt_len.sum() > 0 ? (static_cast<double>(reverse_stats.fwd_pkt_len.sum()) / reverse_stats.fwd_pkt_count) : 0.0,
                     reverse_stats.fwd_pkt_count > 0 ? (static_cast<double>(reverse_stats.fwd_pkt_count) / reverse_stats.fwd_pkt_count) : 0.0,
                     flow_duration > 0 ? (static_cast<double>(reverse_stats.fwd_pkt_count) / flow_duration) : 0.0,
                     stats.fwd_pkt_count, stats.fwd_pkt_len.sum(), reverse_stats.fwd_pkt_count, reverse_stats.fwd_pkt_len.sum(),
                     stats.init_win_bytes_forward, reverse_stats.init_win_bytes_forward, stats.act_data_pkt_fwd, stats.min_seg_size_forward,
                     stats.fwd_ipd.avg(), stats.fwd_ipd.std(), stats.fwd_ipd.max(), stats.fwd_ipd.min(),
                     reverse_stats.fwd_ipd.avg(), reverse_stats.fwd_ipd.std(), reverse_stats.fwd_ipd.max(), reverse_stats.fwd_ipd.min(),
                     benigns.find(flow_id) != benigns.end() ? "BENIGN" : "ATTACK");
    }
    std::printf("Finished processing %s\n", argv[1]);
    pcap_close(cap), std::fclose(csv);
    return 0;
}
