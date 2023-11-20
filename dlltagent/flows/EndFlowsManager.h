/*
 * EndFlowsManager.h
 *
 *  Created on: June 6, 2023
 *      Author: rodolk
 */

#ifndef END_FLOWSMANAGER_H_
#define END_FLOWSMANAGER_H_

#include <mutex>

#include "flow.h"
#include "FlowsManager.h"

using namespace std;

namespace flows {

class EndFlowsManager: public FlowsManager {
public:

    EndFlowsManager();
    virtual ~EndFlowsManager();

    void init() {
        std::unique_lock<std::mutex> lck(flowArrayMtx_);
        FlowsManager::init("end_flows");
    }

    void addNewFlow(end_flow_t *endFlow);

private:
    end_flow_t flowArray_[MAX_FLOW_POS];

    void dumpFlows(uint32_t init, uint32_t end, bool doFlush);

};
} //namespace flows

#endif /* END_FLOWSMANAGER_H_ */
