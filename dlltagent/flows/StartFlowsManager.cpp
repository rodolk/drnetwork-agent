/*
 * StartFlowsManager.cpp
 *
 *  Created on: June 6, 2023
 *      Author: rodolk
 */

#include "StartFlowsManager.h"

#include <iostream>
#include <fstream>

#include "interface.h"
#include "ipconst.h"

namespace flows {

StartFlowsManager::StartFlowsManager() {
    // TODO Auto-generated constructor stub

}

StartFlowsManager::~StartFlowsManager() {
    // TODO Auto-generated destructor stub
}

void StartFlowsManager::dumpFlows(uint32_t init, uint32_t end, bool doFlush) {
    uint32_t idx;
    char data[100];

    logFileManager_->processRotation();
    ofstream& flowsFile = logFileManager_->getFileStream();

    for(idx = init; idx < end; idx++) {
        const char *resIP = inet_ntop(AF_INET, (const void *)(flowArray_[idx].ipSrc), data, INET_ADDRSTRLEN + 1);
        if (resIP == NULL) {

        }

        flowsFile << data << "," << flowArray_[idx].portSrc << ",";

        resIP = inet_ntop(AF_INET, (const void *)(flowArray_[idx].ipDst), data, INET_ADDRSTRLEN + 1);
        if (resIP == NULL) {

        }

        flowsFile << data << "," << flowArray_[idx].portDst << ',';
        flowsFile << flowArray_[idx].process.pid << "," << flowArray_[idx].process.ppid << "," << flowArray_[idx].process.uid
                << "," << flowArray_[idx].process.shortName << ",";
        flowsFile << flowArray_[idx].timeStamp.tv_sec << ',' << flowArray_[idx].timeStamp.tv_usec << "," << flowArray_[idx].fromInternet << ","
                << Configuration::getInstance().pcapDevice << std::endl;

        logFileManager_->incLine();

        dumpedFlowsCounter_++;
    }

    if (doFlush) {
        logFileManager_->flush();
    }
}

void StartFlowsManager::addNewFlow(flow_t *onlyIPsAndPorts, struct timeval *timeStamp, int32_t pid, int32_t ppid, uint32_t uid, const char *shortName) {
    struct timeval timeNow;
    uint32_t ipOther;

    std::unique_lock<std::mutex> lck(flowArrayMtx_);
    memcpy(&flowArray_[flowIdx_], onlyIPsAndPorts, SIZE_OF_IP_PORT);
    flowArray_[flowIdx_].timeStamp = *timeStamp;

    ipOther = *((uint32_t *)onlyIPsAndPorts->ipSrc);
    if (Interface::isLocal(ipOther)) {
        flowArray_[flowIdx_].fromInternet = '0';
        ipOther = *((uint32_t *)onlyIPsAndPorts->ipDst);
    } else {
        if (!Interface::isFromInternet(*((uint32_t *)onlyIPsAndPorts->ipSrc), *((uint32_t *)onlyIPsAndPorts->ipDst))) {
            flowArray_[flowIdx_].fromInternet = '0';
        } else {
            flowArray_[flowIdx_].fromInternet = '1';
        }
    }
    flowArray_[flowIdx_].process.pid = pid;
    flowArray_[flowIdx_].process.ppid = ppid;
    flowArray_[flowIdx_].process.uid = uid;
    strcpy(flowArray_[flowIdx_].process.shortName, shortName);

    getTimestampNow(timeNow);
    if (timeNow.tv_sec - lastTimeIPsMap_.tv_sec > 180) {
        idxIPsMap_ = idxIPsMap_ ^ 0x1;
        seenIPsMap_[idxIPsMap_].clear();
        lastTimeIPsMap_.tv_sec = timeNow.tv_sec;
    }

    //char buf[100];
    //inet_ntop(AF_INET, &ipOther, buf, 99);
    seenIPsMap_[idxIPsMap_][ipOther] = timeNow.tv_sec;

    flowIdx_++;
    if (flowIdx_ == HALF_FLOW_POS) {
        dumpFlows(0, HALF_FLOW_POS, true);
        lastTimeDump_.tv_sec = timeNow.tv_sec;
    } else if (flowIdx_ == MAX_FLOW_POS) {
        dumpFlows(HALF_FLOW_POS, MAX_FLOW_POS, true);
        lastTimeDump_.tv_sec = timeNow.tv_sec;
        flowIdx_ = 0;
    }
}

/*
std::function<void (const struct timeval&)> StartFlowsManager::getTimedAction() {
    return [&](const struct timeval& timeNow) -> void {
        std::unique_lock<std::mutex> lck(flowArrayMtx_);
        if (flowIdx_ == 0) return;
        if (timeNow.tv_sec - lastTimeDump_.tv_sec > 60) {
            dumpFlows(0, flowIdx_, true);
            lastTimeDump_.tv_sec = timeNow.tv_sec;
            //Caution: be careful here if we decide to dump in parallel with a different thread
            flowIdx_ = 0;
            ApplicationLog::getLog().info("TOTAL Flows saved since start: %d\n", dumpedFlowsCounter_);
        }
    };
}
*/

} //namespace flows


