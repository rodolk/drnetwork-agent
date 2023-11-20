/*
 * FlowProcessManager.h
 *
 *  Created on: June 6, 2023
 *      Author: rodolk
 */

#ifndef FLOW_PROCESS_MANAGER_H_
#define FLOW_PROCESS_MANAGER_H_

#include <mutex>

#include "ebpf_proc_common.h"
#include "FlowsManager.h"

using namespace std;

namespace flows {

class FlowProcessManager: public FlowsManager {
public:

    FlowProcessManager();
    virtual ~FlowProcessManager();

    void init() {
        std::unique_lock<std::mutex> lck(flowArrayMtx_);
        FlowsManager::init("process_flows");
    }

    void addNewFlow(struct tcpconn__ProcessConnEBPF *tcpconn);

private:
    struct tcpconn_tracked {
        struct tcpconn__ProcessConnEBPF tcpconn;
        struct timeval trackTimestamp;
    };
    struct tcpconn_tracked flowArray_[MAX_FLOW_POS];

    void dumpFlows(uint32_t init, uint32_t end, bool doFlush);

};
} //namespace flows

#endif /* FLOW_PROCESS_MANAGER_H_ */
