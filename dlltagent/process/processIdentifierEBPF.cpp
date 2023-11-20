/*
 * processIdentifierEBPF.cpp
 *
 *  Created on: Dec 17, 2021
 *      Author: rodolk
 */

#include "processIdentifierEBPF.h"

#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <linux/bpf.h>
//#include <bpf/bpf.h>
//#include <bpf/libbpf.h>
//#include "sock_example.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>
#include <dlfcn.h>

#include "processConnectEBPF.h"
#include "Configuration.h"
#include "applicationLog.h"


#define LIB_EBPF "libdlltebpf.so"
#define LIBBPF "libbpf"

struct bpf_object *gBpfObj;
struct bpf_program *gProgProbe;
struct bpf_program *gProgRetProbe;
struct bpf_link *gLinkProgProbe;
struct bpf_link *gLinkProgRetProbe;
int mapIndexfd;
int mapTCPConnfd;


ProcessIdentifierEBPF::~ProcessIdentifierEBPF() {
    cleanAll();
    if (dlHandle_) dlclose(dlHandle_);
}

static int (*initialize_ProcessConnEBPF) (const char *, const char *, const char *, unsigned int);
static int (*retrieveNextTCPConnection) (struct tcpconn__ProcessConnEBPF *);
static int (*cleanAll_ProcessConnEBPF) (void);

int ProcessIdentifierEBPF::initializeSpecific() {
    dlHandle_ = dlopen(LIB_EBPF, RTLD_NOW);
    if (NULL == dlHandle_) {
        const char *dlerrorPtr = dlerror();
        ApplicationLog::getLog().debug("Error loading shared library %s: %s\n", LIB_EBPF, dlerrorPtr);
        if (strstr(dlerrorPtr, LIBBPF)) {
            ApplicationLog::getLog().error("Error related to loading shared library %s\n", LIBBPF);
            errorStr_ = dlerrorPtr;
            return -10;
        }
        string absPathName;
        auto libPathIter = Configuration::getInstance().libPathList.begin();
        while(NULL == dlHandle_ && libPathIter != Configuration::getInstance().libPathList.end()) {
            absPathName = *libPathIter + "/" + LIB_EBPF;
            ApplicationLog::getLog().debug("Searching shared library: %s\n", absPathName.c_str());
            dlHandle_ = dlopen(absPathName.c_str(), RTLD_NOW);
            if (NULL == dlHandle_) {
                dlerrorPtr = dlerror();
                ApplicationLog::getLog().debug("Error loading shared library %s: %s\n", absPathName.c_str(), dlerrorPtr);
                if (strstr(dlerrorPtr, LIBBPF)) {
                    ApplicationLog::getLog().error("Error related to loading shared library %s\n", LIBBPF);
                    errorStr_ = dlerrorPtr;
                    return -10;
                }
            }
            libPathIter++;
        }
        if (NULL == dlHandle_) {
            ApplicationLog::getLog().debug("Could not load shared library %s\n", LIB_EBPF);
            errorStr_ = dlerrorPtr;
            return -1;
        }
    }

    dlerror();

    initialize_ProcessConnEBPF = (int (*) (const char *, const char *, const char *, unsigned int))dlsym(dlHandle_, "initialize_ProcessConnEBPF");

    if (NULL == initialize_ProcessConnEBPF) {
        errorStr_ = dlerror();
        dlclose(dlHandle_);
        return -2;
    }
    dlerror();

    retrieveNextTCPConnection = (int (*) (struct tcpconn__ProcessConnEBPF *))dlsym(dlHandle_, "retrieveNextTCPConnection");

    if (NULL == retrieveNextTCPConnection) {
        errorStr_ = dlerror();
        dlclose(dlHandle_);
        return -3;
    }
    dlerror();

    cleanAll_ProcessConnEBPF = (int (*) (void))dlsym(dlHandle_, "cleanAll_ProcessConnEBPF");

    if (NULL == cleanAll_ProcessConnEBPF) {
        errorStr_ = dlerror();
        dlclose(dlHandle_);
        return -4;
    }
    dlerror();

    int res = initialize_ProcessConnEBPF(Configuration::getInstance().ebpfObjectPath.c_str(), Configuration::getInstance().logsDirectory.c_str(), "processEBPF", (unsigned int)DaemonLog::LOGLevelInfo);
    if (res == 0) {
        initialized_ = true;
    }

    return res;
}

/*
 *     Caution: connectingDataMutex_ locked before calling this function. This function must not
 *              lock connectingDataMutex_
 *
 */
int ProcessIdentifierEBPF::updateNewConnections(int numReadConn) {
    struct tcpconn__ProcessConnEBPF tcpconnData;
    int count = 0;
    int count2 = 0;
    int newConn;
    bool found;

    newConn = retrieveNextTCPConnection(&tcpconnData);

    while(newConn == 1) {
        //ApplicationLog::getLog().info("Process TGID %d, PID %d, PPID %d, UID %u\n", tcpconnData.tgid, tcpconnData.pid, tcpconnData.ppid, tcpconnData.uid);
        found = false;
        tcpconnData.ppid = -1; //We cannot get PPID with ebpf, at least in Ubuntu.
        count++;
        if (localDevIP_ == tcpconnData.saddr) {
            count2++;
            auto iterAddr = pendingSearchMap_.find(tcpconnData.saddr);
            if (iterAddr != pendingSearchMap_.end()) {
                auto iterPort = iterAddr->second.find(tcpconnData.lport);
                if (iterPort != iterAddr->second.end()) {
                    found = true;
                    PendingSearch ps = iterPort->second;
                    if (setProcessData(tcpconnData)) {
                        *ps.skbPIDPtr = tcpconnData.tgid;
                    } else {
                        *ps.skbPIDPtr = -2;
                    }
                    pendingSearchList_.erase(ps.iter);
                    iterAddr->second.erase(iterPort);
                    //if (iterAddr->second.empty()) we don't erase this element in pendingSearchMap_ because we have few IP addresses
                }
            }
            if (!found) {
                if (setProcessData(tcpconnData)) {
                    setSrcLocalPortData(tcpconnData.saddr, tcpconnData.lport, tcpconnData.tgid);
                } else {
                    ApplicationLog::getLog().error("Process TGID %d, PID %d, already registered with different process attributes\n", tcpconnData.tgid, tcpconnData.pid);
                    uint8_t *ipB = (uint8_t *)&tcpconnData.saddr;
                    ApplicationLog::getLog().error("Process owning socket with src IP %.2d.%.2d.%.2d.%.2d port %u\n",
                            ipB[0], ipB[1], ipB[2], ipB[3], tcpconnData.lport);
                    setSrcLocalPortData(tcpconnData.saddr, tcpconnData.lport, -2);
                }
            }

            flowProcessManager_.addNewFlow(&tcpconnData);
        }
        if (count >= numReadConn && count2 > 0) {
            break;
        }

        newConn = retrieveNextTCPConnection(&tcpconnData);
    }

    return count;
}


int ProcessIdentifierEBPF::cleanAll() {
    if (dlHandle_) {
        ApplicationLog::getLog().debug("Cleaning ebpf processIndetifier\n");
        if (initialized_) {
            int res = cleanAll_ProcessConnEBPF();
            return res;
        }
    }
    return 0;
}


