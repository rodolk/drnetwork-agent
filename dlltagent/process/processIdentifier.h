/*
 * processIdentifier.h
 *
 *  Created on: Apr 15, 2021
 *      Author: rodolk
 */

#ifndef PROCESSIDENTIFIER_H_
#define PROCESSIDENTIFIER_H_

#include <map>
#include <mutex>

#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "applicationLog.h"

#define MAX_PROCESS_LIFE_SEC 28800 //8hs
#define NO_PROCESS_PID -100

class ProcessIdentifier {
public:
    struct ProcessData {
        int32_t pid;
        std::string shortName;
        std::string longCmd;
        int32_t ppid;
        uint32_t uid;
        uint32_t lastTime;
    };
    struct ListenPID {
        int32_t pid;
        uint32_t lastTime;
    };
    ProcessIdentifier();
    virtual ~ProcessIdentifier();

    int initialize() {
        //initializeCmd();
        return initializeSpecific();
    }

    ProcessData getListenProcessFromIPPort(uint32_t localIPAddr, uint16_t localPort) {
        ProcessData pd = {NO_PROCESS_PID, "?", "?", NO_PROCESS_PID, 0xFFFFFFFF, 0};
        listenPIDMutex_.lock();
        auto itPort = listenIPPortPidMap_.find(localIPAddr);
        if (itPort != listenIPPortPidMap_.end()) {
            auto itData = itPort->second.find(localPort);
            if (itData != itPort->second.end()) {
                int32_t pid = itData->second.pid;
                listenPIDMutex_.unlock();
                return getProcessData(pid);
            }
        }
        listenPIDMutex_.unlock();
        return pd;
    }

    virtual bool isListenProcessIdentified(uint32_t localIPAddr, uint16_t localPort) {
        ProcessData pd = getListenProcessFromIPPort(localIPAddr, localPort);
        if (pd.pid == NO_PROCESS_PID) {
            return false;
        }
        return true;
    }


    virtual ProcessData identifyListenProcess(uint32_t localIPAddr, uint16_t localPort) {
        //printf("Looking for %X - %d\n", localIPAddr, localPort);
        ProcessData pd = getListenProcessFromIPPort(localIPAddr, localPort);
        if (pd.pid == NO_PROCESS_PID) {
            executeIdentificationTask(localIPAddr, localPort);
            pd = getListenProcessFromIPPort(localIPAddr, localPort);
        }
        return pd;
    }

    ProcessData getProcessData(int32_t pid) {
        unique_lock<mutex> lock(pidProcessDataMutex_);
        auto iter = pidProcessDataMap_.find(pid);
        if (iter != pidProcessDataMap_.end()) {
            ProcessData ps = iter->second;
            return ps;
        } else {
            ProcessData ps = {NO_PROCESS_PID, "?", "?", NO_PROCESS_PID, 0xFFFFFFFF, 0};
            return ps;
        }
    }

    virtual void identifyConnectingLocalProcess(uint32_t localIPAddr, uint16_t localPort, int32_t *skbPIDPtr) {return;}

    virtual void deletePending(uint32_t localIPAddr, uint16_t localPort) {return;}

    virtual void identifyAllProcesses();

protected:
    std::mutex connectingDataMutex_;

    void setPortData(uint32_t localIPAddr, uint16_t localPort, int32_t pid);

    bool populateProcess(int32_t pid, const char *pidStr, const char *shortName) {
        ProcessData pd = getProcessData(pid);
        if (pd.pid == NO_PROCESS_PID) {
            int32_t ppid;
            uint32_t uid;
            if (getProcessCmd(pidStr, &ppid, &uid)) {
                if (setProcessData(pid, ppid, uid, shortName)) {
                    return true;
                }
            }
        }
        return false;
    }

/*
    const ProcessData *identifyProcessForIPPort(uint32_t localIPAddr, uint16_t localPort) {
        dataMutex_.lock();
        auto itPort = ipPortProcessMap_.find(localIPAddr);
        if (itPort != ipPortProcessMap_.end()) {
            auto itData = itPort->second.find(localPort);
            if (itData != itPort->second.end()) {
                dataMutex_.unlock();
                return &itData->second;
            }
        }
        dataMutex_.unlock();
        return nullptr;
    }
*/

    /*
     * Caution: we are not protecting access to ipPortPidMap_ because the calling function is alread assuring
     * mutual exclusion with connectingDataMutex_
     * However, if identifyPidForSrcIPPort is called from any other function, we must assure mutual exclusion here.
     * If ipPortPidMap_ is accessed in any function other than setSrcLocalPortData and identifyPidForSrcIPPort,
     * then we may need to protect access to ipPortPidMap_
     *
     */
    int32_t identifyPidForSrcIPPort(uint32_t localIPAddr, uint16_t localPort) {
        auto itAddr = ipPortPidMap_.find(localIPAddr);
        if (itAddr != ipPortPidMap_.end()) {
            auto itPort = itAddr->second.find(localPort);
            if (itPort != itAddr->second.end()) {
                int32_t retPid = itPort->second;
                itAddr->second.erase(itPort);
                //We don't erase the element pointed by itAddr in ipPortPidMap_
                return retPid;
            }
        }
        return -1;
    }

    /*
     * Caution: we are not protecting access to ipPortPidMap_ because the calling function is alread assuring
     * mutual exclusion with connectingDataMutex_
     * However, if setSrcLocalPortData is called from any other function, we must assure mutual exclusion here.
     * If ipPortPidMap_ is accessed in any function other than setSrcLocalPortData and identifyPidForSrcIPPort,
     * then we may need to protect access to ipPortPidMap_
     *
     */
    void setSrcLocalPortData(uint32_t localIPAddr, uint16_t localPort, int32_t pid) {
        if (ipPortPidMap_[localIPAddr].size() > 1000) {
            ApplicationLog::getLog().warning("ipPortPidMap_ for IP addr %X, grew beyond 1,000 elements, there is a performance issue\n", localIPAddr);
            ApplicationLog::getLog().warning("I will clear data structure ipPortPidMap_\n");
            for(auto& it : ipPortPidMap_) {
                it.second.clear();
            }
        }
        ipPortPidMap_[localIPAddr][localPort] = pid;
    }


    bool setProcessData(int32_t pid, int32_t ppid, uint32_t uid, const char *comm) {
        unique_lock<mutex> lock(pidProcessDataMutex_);
        if (pidProcessDataMap_.size() > 3000) {
            ApplicationLog::getLog().warning("pidProcessDataMap_ size is %d > 3000. Will clear data\n", pidProcessDataMap_.size());
            uint32_t nowSeconds = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            auto iter = pidProcessDataMap_.begin();
            while (iter != pidProcessDataMap_.end()) {
                if ((nowSeconds - iter->second.lastTime) > 3600) {
                    auto iterDel = iter;
                    ++iter;
                    pidProcessDataMap_.erase(iterDel);
                } else {
                    ++iter;
                }
            }
            ApplicationLog::getLog().warning("pidProcessDataMap_ size is %d after clearing data older than 1 hr\n", pidProcessDataMap_.size());
            if (pidProcessDataMap_.size() > 2000) {
                ApplicationLog::getLog().warning("pidProcessDataMap_ size is %d > 2000, after clearing data. Will clear data again\n", pidProcessDataMap_.size());
                uint32_t nowSeconds = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
                auto iter = pidProcessDataMap_.begin();
                while (iter != pidProcessDataMap_.end()) {
                    if ((nowSeconds - iter->second.lastTime) > 600) {
                        auto iterDel = iter;
                        ++iter;
                        pidProcessDataMap_.erase(iterDel);
                    } else {
                        ++iter;
                    }
                }
                ApplicationLog::getLog().warning("pidProcessDataMap_ size is %d after clearing data older than 10 min\n", pidProcessDataMap_.size());
            }
        }
        auto iter = pidProcessDataMap_.find(pid);
        if (iter == pidProcessDataMap_.end()) {
            pidProcessDataMap_[pid].pid = pid;
            pidProcessDataMap_[pid].shortName = comm;
            pidProcessDataMap_[pid].longCmd = "";
            pidProcessDataMap_[pid].lastTime = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            pidProcessDataMap_[pid].ppid = ppid;
            pidProcessDataMap_[pid].uid = uid;
            return true;
        } else {
            if (iter->second.shortName == comm && iter->second.uid == uid) { //(ppid < 0 || iter->second.ppid == ppid) &&
                pidProcessDataMap_[pid].lastTime = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
                return true;
            } else {
                uint32_t nowSeconds = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
                if (nowSeconds > iter->second.lastTime && ((nowSeconds - iter->second.lastTime) < MAX_PROCESS_LIFE_SEC)) {
                    ApplicationLog::getLog().error("Error: process ID %d, already exists with DIFFERENT process attributes\n", pid);
                    ApplicationLog::getLog().error("Error: Existing process comm: %s, PPID: %d, UID: %u\n", iter->second.shortName.c_str(), iter->second.ppid, iter->second.uid);
                    ApplicationLog::getLog().error("Error: Received process comm: %s, PPID: %d, UID: %u\n", comm, ppid, uid);
                    return false;
                } else { //Else change the data for this PID
                    ApplicationLog::getLog().info("process ID %d, already exists with DIFFERENT process attributes (comm: %s) but it's old. We'll change for a new one (comm: %s)\n",
                            pid, pidProcessDataMap_[pid].shortName.c_str(), comm);
                    pidProcessDataMap_[pid].pid = pid;
                    pidProcessDataMap_[pid].shortName = comm;
                    pidProcessDataMap_[pid].longCmd = "";
                    pidProcessDataMap_[pid].lastTime = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
                    pidProcessDataMap_[pid].ppid = ppid;
                    pidProcessDataMap_[pid].uid = uid;
                    return true;
                }
            }
        }
    }


private:
    static const int SYSTEM_OUTPUT_LINE_VALUE = 1000;
    //std::map<uint32_t, std::map<uint16_t, ProcessData>> ipPortProcessMap_;
    std::map<uint32_t, std::map<uint16_t, ListenPID>> listenIPPortPidMap_;
    std::map<uint32_t, std::map<uint16_t, int32_t>> ipPortPidMap_;
    std::map<int32_t, ProcessData> pidProcessDataMap_;
    uint32_t spaceLocalAddress_{0}; //Position of local address:port in netstat -natp command
    uint32_t spacePID_{0}; //Position of pid in netstat -natp command
    char *systemOutputLine1_;
    char *systemOutputLine2_;
    uint32_t sysOutLineLen_{SYSTEM_OUTPUT_LINE_VALUE};
    bool netstatExists_{false};
    std::mutex pidProcessDataMutex_;
    std::mutex listenPIDMutex_;


    void executeIdentificationTask(uint32_t localIPAddr, uint16_t localPort) {
        char localIPAddrCStr[40];
        inet_ntop(AF_INET, &localIPAddr, localIPAddrCStr, 40);

        identifyProcessForPort(localIPAddr, localIPAddrCStr, localPort);
    }

    virtual int initializeSpecific();

    void populateNextProcess(const char *outputLine, uint32_t spaceLocalAddress, uint32_t spacePID);
    uint32_t get_line(char **buffer, uint32_t *len, FILE *fp);
    bool getProcessCmd(const char *pid, int32_t *ppid, uint32_t *uid);
    virtual void identifyProcessForPort(uint32_t localIPAddr, const char *localIP, uint16_t localPort);
    int initializeCmd();
    void identifyProcessesWithCmd(const char *cmd);

};

#endif /* PROCESSIDENTIFIER_H_ */
