#ifndef FEATURES_H
#define FEATURES_H

#include <string>
#include <vector>
#include <iostream>
#include <stdexcept>

enum class FlowFeature
{
    FID,
    SRC_IP,
    SRC_PORT,
    DST_IP,
    DST_PORT,
    PROTOCOL,
    TIMESTAMP,
    FLOW_DURATION,
    TOT_FWD_PKTS,
    TOT_BWD_PKTS,
    TOT_LEN_FWD_PKTS,
    TOT_LEN_BWD_PKTS,
    FWD_PKT_LEN_MAX,
    FWD_PKT_LEN_MIN,
    FWD_PKT_LEN_MEAN,
    FWD_PKT_LEN_STD,
    BWD_PKT_LEN_MAX,
    BWD_PKT_LEN_MIN,
    BWD_PKT_LEN_MEAN,
    BWD_PKT_LEN_STD,
    FLOW_BYTES_S,
    FLOW_PKTS_S,
    FLOW_IAT_MEAN,
    FLOW_IAT_STD,
    FLOW_IAT_MAX,
    FLOW_IAT_MIN,
    FWD_IAT_TOTAL,
    FWD_IAT_MEAN,
    FWD_IAT_STD,
    FWD_IAT_MAX,
    FWD_IAT_MIN,
    BWD_IAT_TOTAL,
    BWD_IAT_MEAN,
    BWD_IAT_STD,
    BWD_IAT_MAX,
    BWD_IAT_MIN,
    FWD_PSH_FLAGS,
    BWD_PSH_FLAGS,
    FWD_URG_FLAGS,
    BWD_URG_FLAGS,
    FWD_HEADER_LEN,
    BWD_HEADER_LEN,
    FWD_PKTS_S,
    BWD_PKTS_S,
    PKT_LEN_MIN,
    PKT_LEN_MAX,
    PKT_LEN_MEAN,
    PKT_LEN_STD,
    PKT_LEN_VAR,
    FIN_CNT,
    SYN_CNT,
    RST_CNT,
    PSH_CNT,
    ACK_CNT,
    URG_CNT,
    CWE_CNT,
    ECE_CNT,
    DOWN_UP_RATIO,
    PKT_SIZE_AVG,
    FWD_SEG_SIZE_AVG,
    BWD_SEG_SIZE_AVG,
    FWD_BYTS_BLK_AVG,
    FWD_PKTS_BLK_AVG,
    FWD_BLK_RATE_AVG,
    BWD_BYTS_BLK_AVG,
    BWD_PKTS_BLK_AVG,
    BWD_BLK_RATE_AVG,
    SUBFLOW_FWD_PKTS,
    SUBFLOW_FWD_BYTS,
    SUBFLOW_BWD_PKTS,
    SUBFLOW_BWD_BYTS,
    INIT_FWD_WIN_BYTS,
    INIT_BWD_WIN_BYTS,
    FWD_ACT_DATA_PKTS,
    FWD_SEG_SIZE_MIN,
    ACTIVE_MEAN,
    ACTIVE_STD,
    ACTIVE_MAX,
    ACTIVE_MIN,
    IDLE_MEAN,
    IDLE_STD,
    IDLE_MAX,
    IDLE_MIN,
    LABEL
};

class FlowFeatureInfo
{
public:
    static const std::vector<std::pair<FlowFeature, std::string>> &getNames()
    {
        static std::vector<std::pair<FlowFeature, std::string>> names{
            {FlowFeature::FID, "Flow ID"},
            {FlowFeature::SRC_IP, "Src IP"},
            {FlowFeature::SRC_PORT, "Src Port"},
            {FlowFeature::DST_IP, "Dst IP"},
            {FlowFeature::DST_PORT, "Dst Port"},
            {FlowFeature::PROTOCOL, "Protocol"},
            {FlowFeature::TIMESTAMP, "Timestamp"},
            {FlowFeature::FLOW_DURATION, "Flow Duration"},
            {FlowFeature::TOT_FWD_PKTS, "Tot Fwd Pkts"},
            {FlowFeature::TOT_BWD_PKTS, "Tot Bwd Pkts"},
            {FlowFeature::TOT_LEN_FWD_PKTS, "TotLen Fwd Pkts"},
            {FlowFeature::TOT_LEN_BWD_PKTS, "TotLen Bwd Pkts"},
            {FlowFeature::FWD_PKT_LEN_MAX, "Fwd Pkt Len Max"},
            {FlowFeature::FWD_PKT_LEN_MIN, "Fwd Pkt Len Min"},
            {FlowFeature::FWD_PKT_LEN_MEAN, "Fwd Pkt Len Mean"},
            {FlowFeature::FWD_PKT_LEN_STD, "Fwd Pkt Len Std"},
            {FlowFeature::BWD_PKT_LEN_MAX, "Bwd Pkt Len Max"},
            {FlowFeature::BWD_PKT_LEN_MIN, "Bwd Pkt Len Min"},
            {FlowFeature::BWD_PKT_LEN_MEAN, "Bwd Pkt Len Mean"},
            {FlowFeature::BWD_PKT_LEN_STD, "Bwd Pkt Len Std"},
            {FlowFeature::FLOW_BYTES_S, "Flow Byts/s"},
            {FlowFeature::FLOW_PKTS_S, "Flow Pkts/s"},
            {FlowFeature::FLOW_IAT_MEAN, "Flow IAT Mean"},
            {FlowFeature::FLOW_IAT_STD, "Flow IAT Std"},
            {FlowFeature::FLOW_IAT_MAX, "Flow IAT Max"},
            {FlowFeature::FLOW_IAT_MIN, "Flow IAT Min"},
            {FlowFeature::FWD_IAT_TOTAL, "Fwd IAT Tot"},
            {FlowFeature::FWD_IAT_MEAN, "Fwd IAT Mean"},
            {FlowFeature::FWD_IAT_STD, "Fwd IAT Std"},
            {FlowFeature::FWD_IAT_MAX, "Fwd IAT Max"},
            {FlowFeature::FWD_IAT_MIN, "Fwd IAT Min"},
            {FlowFeature::BWD_IAT_TOTAL, "Bwd IAT Tot"},
            {FlowFeature::BWD_IAT_MEAN, "Bwd IAT Mean"},
            {FlowFeature::BWD_IAT_STD, "Bwd IAT Std"},
            {FlowFeature::BWD_IAT_MAX, "Bwd IAT Max"},
            {FlowFeature::BWD_IAT_MIN, "Bwd IAT Min"},
            {FlowFeature::FWD_PSH_FLAGS, "Fwd PSH Flags"},
            {FlowFeature::BWD_PSH_FLAGS, "Bwd PSH Flags"},
            {FlowFeature::FWD_URG_FLAGS, "Fwd URG Flags"},
            {FlowFeature::BWD_URG_FLAGS, "Bwd URG Flags"},
            {FlowFeature::FWD_HEADER_LEN, "Fwd Header Len"},
            {FlowFeature::BWD_HEADER_LEN, "Bwd Header Len"},
            {FlowFeature::FWD_PKTS_S, "Fwd Pkts/s"},
            {FlowFeature::BWD_PKTS_S, "Bwd Pkts/s"},
            {FlowFeature::PKT_LEN_MIN, "Pkt Len Min"},
            {FlowFeature::PKT_LEN_MAX, "Pkt Len Max"},
            {FlowFeature::PKT_LEN_MEAN, "Pkt Len Mean"},
            {FlowFeature::PKT_LEN_STD, "Pkt Len Std"},
            {FlowFeature::PKT_LEN_VAR, "Pkt Len Var"},
            {FlowFeature::FIN_CNT, "FIN Flag Cnt"},
            {FlowFeature::SYN_CNT, "SYN Flag Cnt"},
            {FlowFeature::RST_CNT, "RST Flag Cnt"},
            {FlowFeature::PSH_CNT, "PSH Flag Cnt"},
            {FlowFeature::ACK_CNT, "ACK Flag Cnt"},
            {FlowFeature::URG_CNT, "URG Flag Cnt"},
            {FlowFeature::CWE_CNT, "CWE Flag Count"},
            {FlowFeature::ECE_CNT, "ECE Flag Cnt"},
            {FlowFeature::DOWN_UP_RATIO, "Down/Up Ratio"},
            {FlowFeature::PKT_SIZE_AVG, "Pkt Size Avg"},
            {FlowFeature::FWD_SEG_SIZE_AVG, "Fwd Seg Size Avg"},
            {FlowFeature::BWD_SEG_SIZE_AVG, "Bwd Seg Size Avg"},
            {FlowFeature::FWD_BYTS_BLK_AVG, "Fwd Byts/b Avg"},
            {FlowFeature::FWD_PKTS_BLK_AVG, "Fwd Pkts/b Avg"},
            {FlowFeature::FWD_BLK_RATE_AVG, "Fwd Blk Rate Avg"},
            {FlowFeature::BWD_BYTS_BLK_AVG, "Bwd Byts/b Avg"},
            {FlowFeature::BWD_PKTS_BLK_AVG, "Bwd Pkts/b Avg"},
            {FlowFeature::BWD_BLK_RATE_AVG, "Bwd Blk Rate Avg"},
            {FlowFeature::SUBFLOW_FWD_PKTS, "Subflow Fwd Pkts"},
            {FlowFeature::SUBFLOW_FWD_BYTS, "Subflow Fwd Byts"},
            {FlowFeature::SUBFLOW_BWD_PKTS, "Subflow Bwd Pkts"},
            {FlowFeature::SUBFLOW_BWD_BYTS, "Subflow Bwd Byts"},
            {FlowFeature::INIT_FWD_WIN_BYTS, "Init Fwd Win Byts"},
            {FlowFeature::INIT_BWD_WIN_BYTS, "Init Bwd Win Byts"},
            {FlowFeature::FWD_ACT_DATA_PKTS, "Fwd Act Data Pkts"},
            {FlowFeature::FWD_SEG_SIZE_MIN, "Fwd Seg Size Min"},
            {FlowFeature::ACTIVE_MEAN, "Active Mean"},
            {FlowFeature::ACTIVE_STD, "Active Std"},
            {FlowFeature::ACTIVE_MAX, "Active Max"},
            {FlowFeature::ACTIVE_MIN, "Active Min"},
            {FlowFeature::IDLE_MEAN, "Idle Mean"},
            {FlowFeature::IDLE_STD, "Idle Std"},
            {FlowFeature::IDLE_MAX, "Idle Max"},
            {FlowFeature::IDLE_MIN, "Idle Min"},
            {FlowFeature::LABEL, "Label"}};
        return names;
    }

    static std::string getHeader()
    {
        static std::string header;
        if (header.empty())
        {
            for (const auto &pair : getNames())
            {
                header.append(pair.second).append(",");
                // std::cout << pair.second << std::endl; // Debugging output
            }
            if (!header.empty())
            {
                header.pop_back(); // Remove the trailing comma
            }
        }
        return header;
    }

    static std::vector<FlowFeature> getFeatureList()
    {
        return {
            FlowFeature::PROTOCOL,
            FlowFeature::FLOW_DURATION,
            FlowFeature::TOT_FWD_PKTS,
            FlowFeature::TOT_BWD_PKTS,
            FlowFeature::TOT_LEN_FWD_PKTS,
            FlowFeature::TOT_LEN_BWD_PKTS,
            FlowFeature::FWD_PKT_LEN_MAX,
            FlowFeature::FWD_PKT_LEN_MIN,
            FlowFeature::FWD_PKT_LEN_MEAN,
            FlowFeature::FWD_PKT_LEN_STD,
            FlowFeature::BWD_PKT_LEN_MAX,
            FlowFeature::BWD_PKT_LEN_MIN,
            FlowFeature::BWD_PKT_LEN_MEAN,
            FlowFeature::BWD_PKT_LEN_STD,
            FlowFeature::FLOW_BYTES_S,
            FlowFeature::FLOW_PKTS_S,
            FlowFeature::FLOW_IAT_MEAN,
            FlowFeature::FLOW_IAT_STD,
            FlowFeature::FLOW_IAT_MAX,
            FlowFeature::FLOW_IAT_MIN,
            FlowFeature::FWD_IAT_TOTAL,
            FlowFeature::FWD_IAT_MEAN,
            FlowFeature::FWD_IAT_STD,
            FlowFeature::FWD_IAT_MAX,
            FlowFeature::FWD_IAT_MIN,
            FlowFeature::BWD_IAT_TOTAL,
            FlowFeature::BWD_IAT_MEAN,
            FlowFeature::BWD_IAT_STD,
            FlowFeature::BWD_IAT_MAX,
            FlowFeature::BWD_IAT_MIN};
    }

    static std::string featureValueToString(FlowFeature feature, const std::string &value)
    {
        if (feature == FlowFeature::PROTOCOL)
        {
            try
            {
                int number = std::stoi(value);
                if (number == 6)
                {
                    return "TCP";
                }
                else if (number == 17)
                {
                    return "UDP";
                }
                else
                {
                    return "Others";
                }
            }
            catch (const std::invalid_argument &e)
            {
                std::cerr << "Invalid argument: " << e.what() << '\n';
                return "Others";
            }
        }
        return value;
    }
};

#endif // FLOW_FEATURE_H
