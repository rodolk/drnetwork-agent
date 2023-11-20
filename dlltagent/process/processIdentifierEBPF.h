/*
 * processIdentifierEBPF.h
 *
 *  Created on: Dec 17, 2021
 *      Author: rodolk
 */

#ifndef PROCESS_PROCESSIDENTIFIEREBPF_H_
#define PROCESS_PROCESSIDENTIFIEREBPF_H_

#include "processIdentifier.h"
#include "FlowProcessManager.h"


class ProcessIdentifierEBPF: public ProcessIdentifier {
public:
    struct PendingSearch {
        int32_t *skbPIDPtr;
        uint32_t lastTime;
        std::list<PendingSearch>::iterator iter;
    };

    ProcessIdentifierEBPF(flows::FlowProcessManager &flowProcessManager, uint32_t localDevIP) : flowProcessManager_(flowProcessManager), localDevIP_(localDevIP) {};
    virtual ~ProcessIdentifierEBPF();

    std::string& getErrorString() {
        return errorStr_;
    }

    /*
     * Caution: Here we trust skbPIDPtr is a valid pointer to an skb_t->pid. We depend on the calling function
     *
     */
    void identifyConnectingLocalProcess(uint32_t localIPAddr, uint16_t localPort, int32_t *skbPIDPtr) {
        std::unique_lock<mutex> lock(connectingDataMutex_);
        int32_t pidFound = identifyPidForSrcIPPort(localIPAddr, localPort);
        if (pidFound != -1) {
            *skbPIDPtr = pidFound;
            return;
        }
        updateNewConnections(kNumReadConnections);
        pidFound = identifyPidForSrcIPPort(localIPAddr, localPort);

        if (pidFound == -1) {
            if (pendingSearchList_.size() > 1000) {
                ApplicationLog::getLog().warning("pendingSearchList_ grew beyond 1,000 elements, there is a performance issue\n");
                ApplicationLog::getLog().warning("I will clear data structures pendingSearchMap_ and pendingSearchList_ \n");
                for(auto& it : pendingSearchMap_) {
                    it.second.clear();
                }
                pendingSearchList_.clear();
            }
            PendingSearch ps;
            ps.skbPIDPtr = skbPIDPtr;
            ps.lastTime = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            pendingSearchList_.push_back(ps);
            std::list<PendingSearch>::iterator iter = pendingSearchList_.end();
            --iter;
            ps.iter = iter;
            pendingSearchMap_[localIPAddr][localPort] = ps;
        } else {
            *skbPIDPtr = pidFound;
        }
    }

    virtual void deletePending(uint32_t localIPAddr, uint16_t localPort) {
        std::unique_lock<mutex> lock(connectingDataMutex_);
        auto iterAddr = pendingSearchMap_.find(localIPAddr);
        if (iterAddr != pendingSearchMap_.end()) {
            auto iterPort = iterAddr->second.find(localPort);
            if (iterPort != iterAddr->second.end()) {
                PendingSearch ps = iterPort->second;
                pendingSearchList_.erase(ps.iter);
                iterAddr->second.erase(iterPort);
            }
        }
    }


private:
    static const int kNumReadConnections = 5;
    static const int kNumReadConnectionsTask = 10;
    void *dlHandle_{nullptr};
    std::string errorStr_;
    bool initialized_{false};
    flows::FlowProcessManager &flowProcessManager_;
    std::map<uint32_t, std::map<uint16_t, PendingSearch>> pendingSearchMap_;
    std::list<PendingSearch> pendingSearchList_;
    uint32_t localDevIP_;

    int initializeSpecific();
    int updateNewConnections(int numReadConn);
    bool setProcessData(struct tcpconn__ProcessConnEBPF &tcpconnData) {
        return ProcessIdentifier::setProcessData(tcpconnData.tgid, tcpconnData.ppid, tcpconnData.uid, (const char *)tcpconnData.comm);
    }

    int cleanAll();

};

#endif /* PROCESS_PROCESSIDENTIFIEREBPF_H_ */
