// insert to csv file
#ifndef INSERT2CSV_H
#define INSERT2CSV_H

#include <fstream>
#include "flow_generator_listener.h"

class MyFlowGenListener : public FlowGeneratorListener
{
public:
    void on_flow_generated(BasicFlow &flow)
    {
        std::ofstream file;
        file.open("flows.csv", std::ios_base::app);
        file << flow.dump_flow_based_features_ex() << std::endl;
        file.close();
    }
};

#endif // INSERT2CSV_H