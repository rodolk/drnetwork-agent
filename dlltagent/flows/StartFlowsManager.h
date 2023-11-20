/*
 * StartFlowsManager.h
 *
 *  Created on: June 6, 2023
 *      Author: rodolk
 */

#ifndef START_FLOWSMANAGER_H_
#define START_FLOWSMANAGER_H_

#include <mutex>
#include <unordered_map>

#include <arpa/inet.h>

#include "flow.h"
#include "timeHelper.h"
#include "Configuration.h"
#include "FlowsManager.h"


using namespace std;

namespace flows {

class StartFlowsManager: public FlowsManager {
public:

    StartFlowsManager();
    virtual ~StartFlowsManager();

    void init() {
        std::unique_lock<std::mutex> lck(flowArrayMtx_);
        FlowsManager::init("flows");
    }

    void addNewFlow(flow_t *onlyIPsAndPorts, struct timeval *timeStamp, int32_t pid, int32_t ppid, uint32_t uid, const char *shortName);

    bool haveYouSeenThisIPLAstMinute(const char *ipCString) {
        uint32_t addr;
        int i;
        uint32_t idx;
        //TODO:check error
        inet_pton(AF_INET, ipCString, &addr);

        std::unique_lock<std::mutex> lck(flowArrayMtx_);

        for(i = 0, idx = idxIPsMap_; i < 2; i++, idx = idxIPsMap_ ^ 0x01) {
            if (seenIPsMap_[idx].find(addr) != seenIPsMap_[idx].end()) {
                struct timeval timeNow;
                long timeSeen = seenIPsMap_[idx][addr];
                getTimestampNow(timeNow);
                if (timeNow.tv_sec - timeSeen < 60) {
                    return true;
                }
            }
        }
        return false;
    }

    bool haveYouSeenThisIP(const char *ipCString) {
        uint32_t addr;
        int i;
        uint32_t idx;
        //TODO:check error
        inet_pton(AF_INET, ipCString, &addr);

        std::unique_lock<std::mutex> lck(flowArrayMtx_);

        for(i = 0, idx = idxIPsMap_; i < 2; i++, idx = idxIPsMap_ ^ 0x01) {
            if (seenIPsMap_[idx].find(addr) != seenIPsMap_[idx].end()) {
                return true;
            }
        }
        return false;
    }

private:
    flow_t flowArray_[MAX_FLOW_POS];
    std::unordered_map<uint32_t, long> seenIPsMap_[2];
    uint32_t idxIPsMap_{0};
    struct timeval lastTimeIPsMap_{0,0};

    void dumpFlows(uint32_t init, uint32_t end, bool doFlush);

};
} //namespace flows

#endif /* START_FLOWSMANAGER_H_ */
