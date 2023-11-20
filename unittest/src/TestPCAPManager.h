/*
 * TestPCAPManager.h
 *
 *  Created on: Jul 16, 2021
 *      Author: rodolk
 */

#ifndef TESTPCAPMANAGER_H_
#define TESTPCAPMANAGER_H_

#include <iostream>
#include <string>

#include <pcap.h>

#include "PCAPManager.h"

extern uint32_t gDumpedPackets;
extern DaemonLog *daemonLogging;


using namespace std;

class TestPCAPDumper : public PCAPDumper {
    public:

        virtual void savePacket(const struct pcap_pkthdr *pkthdr, const uint8_t *pkt) {
            gDumpedPackets++;
            PCAPDumper::savePacket(pkthdr, pkt);
        }
        TestPCAPDumper(const char *filename) : PCAPDumper(filename) {}
        virtual ~TestPCAPDumper() {}

        friend class TestPCAPManager;

};

class TestPCAPManager : public PCAPManager {
public:
    bool finishOnEndFile{false};
    bool finishedLoop{false};
    std::mutex testPCAPDumperFactoryMtx_;
    std::list<TestPCAPDumper *> testPCAPDumperList_;

    TestPCAPManager() : PCAPManager(daemonLogging) {}
    virtual ~TestPCAPManager() {
        if (pcapFileHandle_) {
            pcap_close(pcapFileHandle_);
        }
    }
    virtual void setup(const char *pcapFilter, const char *pcapDevice) {
        //pcapFilter_ = nullptr;
        //pcapDevice_ = nullptr;
        fname_ = pcapDevice;
    }
    virtual void openPCAP() {
        pcapFileHandle_ = pcap_open_offline(fname_, errbuf);
    }

    //For PCAP Dump tests
    virtual void setPcapFileHandleForDump(const char *fileoffline) {
        pcapFileHandle_ = pcap_open_offline(fileoffline, errbuf);
        if (pcapFileHandle_ == NULL) {
            cout << "Error opening file: " << errbuf << endl;
            throw -1;
        }
    }

    virtual int runLoop(pcap_handler callback, u_char *args) {
        //use -1 instead of 0 as second argument. This is necessary for old pcap libraries.
        int res;
        while(!end) {
            res = pcap_loop(pcapFileHandle_, -1, callback, args);
            if (res < 0) {
                if (res == -1) {
                    char *errStr = pcap_geterr(pcapFileHandle_);
                    cout << "pcap_loop finished with error: " << errStr << endl;
                    end = true;
                } else {
                    cout << "*** pcap_loop finished normally for breakloop ***" << endl;
                    res = 0;
                    end = true;
                }
            } else {
                if (finishOnEndFile) {
                    finishedLoop = true;
                    cout << "pcap_loop finished with non-negative value: " << res << ". Finished reading file\n" << endl;
                } else {
                    cout << "pcap_loop finished with non-negative value: " << res << ". Continue looping\n" << endl;
                }
                end = true;
            }
        }
        return res;
    }

    virtual void endLoop() {
        end = true;
        pcap_breakloop(pcapFileHandle_);
    }

    virtual PCAPDumper *makePCAPDumper(const char *filename) {
        std::unique_lock<std::mutex> lock(testPCAPDumperFactoryMtx_);
        TestPCAPDumper *tpd = new TestPCAPDumper(filename);
        testPCAPDumperList_.push_back(tpd);
        tpd->init(pcapFileHandle_);
        return tpd;
    }

    virtual void releasePCAPDumper(PCAPDumper *pd) {
        std::unique_lock<std::mutex> lock(testPCAPDumperFactoryMtx_);
        TestPCAPDumper *tpd = (TestPCAPDumper *)pd;
        testPCAPDumperList_.remove(tpd);
        delete tpd;
    }

    virtual void cleanup() {
        struct pcap_stat stat;

        fflush(stdout);
        putc('\n', stdout);

        if (pcap_stats(pcapFileHandle_, &stat) < 0) {
            daemonLogging->info("%d packets received by filter\n", stat.ps_recv);
            daemonLogging->info("%d packets dropped by kernel\n", stat.ps_drop);
        }
    }


protected:
    const char *fname_{nullptr};
    pcap_t *pcapFileHandle_{nullptr};
    bool end{false};
    char errbuf[PCAP_ERRBUF_SIZE];
};

#endif /* TESTPCAPMANAGER_H_ */
