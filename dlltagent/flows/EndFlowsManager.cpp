/*
 * EndFlowsManager.cpp
 *
 *  Created on: June 6, 2023
 *      Author: rodolk
 */

#include "EndFlowsManager.h"

#include <iostream>
#include <fstream>

#include <arpa/inet.h>

#include "interface.h"
#include "ipconst.h"

namespace flows {

EndFlowsManager::EndFlowsManager() {
    // TODO Auto-generated constructor stub

}

EndFlowsManager::~EndFlowsManager() {
    // TODO Auto-generated destructor stub
}

void EndFlowsManager::dumpFlows(uint32_t init, uint32_t end, bool doFlush) {
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
        flowsFile << flowArray_[idx].cevt.initTimeStamp.tv_sec << ',' << flowArray_[idx].cevt.initTimeStamp.tv_usec << ",";
        flowsFile << flowArray_[idx].cevt.endTimeStamp.tv_sec << ',' << flowArray_[idx].cevt.endTimeStamp.tv_usec << ",";
        flowsFile << flowArray_[idx].cevt.latency1 << ',' << flowArray_[idx].cevt.latency2 << "," << flowArray_[idx].cevt.latency3 << ','
                << flowArray_[idx].cevt.dataFrom << ',' << flowArray_[idx].cevt.dataTo << ',' << (unsigned short)flowArray_[idx].cevt.connType << ','
                << (unsigned short)flowArray_[idx].cevt.endType << ',' << (unsigned short)flowArray_[idx].cevt.evtSrc << ',' << (unsigned short)flowArray_[idx].cevt.quality << ',';
        flowsFile << flowArray_[idx].process.pid << ',' << flowArray_[idx].process.ppid << ',' << flowArray_[idx].process.uid << ',' << flowArray_[idx].process.shortName
                << std::endl;

        logFileManager_->incLine();

        dumpedFlowsCounter_++;
    }

    if (doFlush) {
        logFileManager_->flush();
    }
}

void EndFlowsManager::addNewFlow(end_flow_t *endFlow) {
    struct timeval timeNow;

    std::unique_lock<std::mutex> lck(flowArrayMtx_);
    memcpy(&flowArray_[flowIdx_], endFlow, sizeof(end_flow_t));

    getTimestampNow(timeNow);

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


} //namespace flows


