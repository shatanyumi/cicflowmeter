// flow generator listener
#ifndef FLOW_GENERATOR_LISTENER_H
#define FLOW_GENERATOR_LISTENER_H
#include "basic_flow.h"

class FlowGeneratorListener
{
public:
    virtual ~FlowGeneratorListener() {}
    virtual void on_flow_generated(BasicFlow &flow) = 0;
};
#endif // FLOW_GENERATOR_LISTENER_H