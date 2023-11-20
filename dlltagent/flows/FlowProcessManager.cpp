/*
 * FlowProcessManager.cpp
 *
 *  Created on: June 6, 2023
 *      Author: rodolk
 */

#include "FlowProcessManager.h"

#include <iostream>
#include <fstream>

#include <arpa/inet.h>

#include "interface.h"
#include "ipconst.h"

namespace flows {

FlowProcessManager::FlowProcessManager() {
    // TODO Auto-generated constructor stub

}

FlowProcessManager::~FlowProcessManager() {
    // TODO Auto-generated destructor stub
}

void FlowProcessManager::dumpFlows(uint32_t init, uint32_t end, bool doFlush) {
    uint32_t idx;
    uint8_t *ipAddrByte;

    logFileManager_->processRotation();
    ofstream& flowsFile = logFileManager_->getFileStream();

    for(idx = init; idx < end; idx++) {
        flowsFile << flowArray_[idx].trackTimestamp.tv_sec << "," << flowArray_[idx].trackTimestamp.tv_usec << ",";
        flowsFile << flowArray_[idx].tcpconn.tgid << "," << flowArray_[idx].tcpconn.pid << "," << flowArray_[idx].tcpconn.comm << "," << flowArray_[idx].tcpconn.ppid << ",";
        flowsFile << flowArray_[idx].tcpconn.uid << ",";
        ipAddrByte = (uint8_t *)&flowArray_[idx].tcpconn.saddr;
        flowsFile << (unsigned short)ipAddrByte[0] << "." << (unsigned short)ipAddrByte[1] << ".";
        //lport is already in host byte order
        flowsFile << (unsigned short)ipAddrByte[2] << "." << (unsigned short)ipAddrByte[3] << "," << flowArray_[idx].tcpconn.lport << ",";
        ipAddrByte = (uint8_t *)&flowArray_[idx].tcpconn.daddr;
        flowsFile << (unsigned short)ipAddrByte[0] << "." << (unsigned short)ipAddrByte[1] << ".";
        //dport is converted from network to host byte order
        flowsFile << (unsigned short)ipAddrByte[2] << "." << (unsigned short)ipAddrByte[3] << "," << ntohs(flowArray_[idx].tcpconn.dport);
        flowsFile << std::endl;

        logFileManager_->incLine();

        dumpedFlowsCounter_++;
    }

    if (doFlush) {
        logFileManager_->flush();
    }
}

void FlowProcessManager::addNewFlow(struct tcpconn__ProcessConnEBPF *tcpconn) {
    struct timeval timeNow;

    std::unique_lock<std::mutex> lck(flowArrayMtx_);
    memcpy(&flowArray_[flowIdx_].tcpconn, tcpconn, sizeof(struct tcpconn__ProcessConnEBPF));

    getTimestampNow(timeNow);
    flowArray_[flowIdx_].trackTimestamp = timeNow;

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


