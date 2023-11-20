/*
 * PCAPManager.h
 *
 *  Created on: Mar 30, 2020
 *      Author: rodolk
 */

#ifndef PCAPMANAGER_H_
#define PCAPMANAGER_H_

#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <list>
#include <mutex>

#include "daemonLog.h"

#include "PCAPDumper.h"

#define MAX_SNAPSHOT_LEN 10000

class PCAPManager {
public:
    PCAPManager(DaemonLog *dl) : log_(dl) {}
    virtual ~PCAPManager();

    virtual void setup(const char *pcapFilter, const char *pcapDevice) {
        int len = strlen(pcapFilter);
        char *aux = (char *)malloc(len + 1);
        memcpy(aux, pcapFilter, len + 1); //include '\0'
        pcapFilter_ = aux;
        len = strlen(pcapDevice);
        aux = (char *)malloc(len + 1);
        memcpy(aux, pcapDevice, len + 1); //include '\0'
        pcapDevice_ = aux;
    }

    virtual int nextFrameTCP(char *msg, struct pcap_pkthdr *hdrPtr)
    {
        char *ptr = NULL;

        while(ptr == NULL)
        {
            ptr = (char *)pcap_next(pcapHandle_, hdrPtr);
        }

        log_->debug("LEN: %d - CAPLEN: %d\n", hdrPtr->len, hdrPtr->caplen);
        memcpy(msg, ptr, hdrPtr->caplen);

        return hdrPtr->caplen;
    }

    virtual int runLoop(pcap_handler callback, u_char *args) {
        //use -1 instead of 0 as second argument. This is necessary for old pcap libraries.
        int res;
        while(!end) {
            res = pcap_loop(pcapHandle_, -1, callback, args);
            if (res < 0) {
                if (res == -1) {
                    char *errStr = pcap_geterr(pcapHandle_);
                    log_->error("pcap_loop finished with error: %s\n", errStr);
                    end = true;
                } else {
                    log_->info("*** pcap_loop finished normally for breakloop ***\n");
                    res = 0;
                    end = true;
                }
            } else {
                log_->info("pcap_loop finished with non-negative value: %d. Continue looping\n", res);
            }
        }
        return res;
    }

    virtual void openPCAP();
    virtual void cleanup();
    virtual void endLoop() {
        end = true;
        cout << "PCAPManager::endLoop" << endl;
        pcap_breakloop(pcapHandle_);
        cout << "PCAPManager::endLoop-2" << endl;
        log_->warning("PCAPManager::endLoop\n");
    }

    virtual PCAPDumper *makePCAPDumper(const char *filename) {
        std::unique_lock<std::mutex> lock(pcapDumperFactoryMtx_);
        PCAPDumper *pd = new PCAPDumper(filename);
        pcapDumperList_.push_back(pd);
        pd->init(pcapHandle_);
        return pd;
    }

    virtual void releasePCAPDumper(PCAPDumper *pd) {
        std::unique_lock<std::mutex> lock(pcapDumperFactoryMtx_);
        pcapDumperList_.remove(pd);
        delete pd;
    }


private:
    pcap_t *pcapHandle_{nullptr};
    const char *pcapFilter_{nullptr}; //Filtering command including '\0'
    const char *pcapDevice_{nullptr}; //PCAP network device including '\0'
    int datalink_;
    int promiscSetting_{0};
    int snaplen_ = MAX_SNAPSHOT_LEN;
    DaemonLog *log_;
    std::list<PCAPDumper *> pcapDumperList_;
    bool end{false};
    std::mutex pcapDumperFactoryMtx_;
};

#endif /* PCAPMANAGER_H_ */
