/*
 * packetSniffer.h
 *
 *  Created on: Mar 30, 2020
 *      Author: rodolk
 */

#ifndef PACKETSNIFFER_H_
#define PACKETSNIFFER_H_

#include <mutex>
#include <thread>
#include <condition_variable>
#include <map>
#include <chrono>
#include <ctime>
#include <sstream>
#include <iostream>
#include <fstream>
#include <unordered_map>
#include <algorithm>
#include <functional>

#include "Connector.h"
#include "skb.h"
#include "queue.h"
#include "PCAPManager.h"
#include "daemonLog.h"
#include "memoryManager.h"
#include "fastQueue.h"
#include "trigger_alg/TriggerAlgorithm.h"
#include "processIdentifier.h"
#include "ipconst.h"
#include "timeHelper.h"
#include "StartFlowsManager.h"
#include "EndFlowsManager.h"
#include "FlowProcessManager.h"
#include "ManagedObject.h"
#include "thirdparty/include/trigger_alg/ThrottleLogarithmic.h"
#include "thirdparty/include/trigger_alg/Throttle.h"
#include "Configuration.h"
#include "interface.h"

#define HOURS_COUNTER_RESET 24

#define FIN_FLAG 1
#define SYN_FLAG 2
#define RST_FLAG 4
#define PSH_FLAG 8
#define ACK_FLAG 16

#define MAX_NUM_THR 1
#define NUM_PROCESS_IDENTIFIER_THR 3
#define MAX_EVT_PROCESSOR_THR 1
#define MAX_SKB_DUMPER_THR 3

#define MAX_NUM_MSG_BUF 300
#define MAX_NUM_EVT 120
#define MAX_NUM_SKB_HOLDER 30
#define MAX_MSG_LEN 10000
#define MAX_EVENT_MSG_LEN 20000
#define MIN_TCP_SIZE 52 //12: Ethernet - 20: IP - 20: TCP

#define NUM_HTTP_DATA_BUFFERS 200
#define NUM_HTTP_DATA_BUFFERS_ADD 10
#define TCP_HDR_BASIC_LEN 5

#define SKB_MAX_COUNT_FB 3
//TODO: check this number please!
#define NUM_FRAME_BUFFER 500

#define EVENT_CODE_SIZE 5

#define CODE_TCP_SYN_BEGIN              "00000"
#define CODE_TCP_SYN_RETRANS_STR        "00001"
#define CODE_TCP_RESET_STR              "00002"
#define CODE_TCP_IS_TLS_STR             "00003"
#define CODE_TLS_ALERT_STR              "00004"
#define CODE_TLS_EXCEP_STR              "00005"
#define CODE_TCP_PARTIAL_CONNECTION_STR "00006"
#define CODE_TCP_ESTABLISHED_STALE_STR  "00007"
#define CODE_TCP_ESTABLISHED_STALE2_STR "00008"
#define CODE_TCP_SYN_RESET_STR          "00009"
#define CODE_TCP_RESET_ABNORMAL_STR     "00010"
#define CODE_VIF_DISAPPEARED            "00011"
#define CODE_TCP_END                    "00012"

#define IS_HTTP(p) (p == 80 || p == 8080)
#define IS_HTTPS(p) (p == 443)

#undef GDB_SRV

class PacketSniffer : public management::ManagedObject {
public:
    static void runAgentThread(PacketSniffer *packetSniffer);
    PacketSniffer();
    virtual ~PacketSniffer();


    static void processPCAPPacketCallback(u_char *args, const struct pcap_pkthdr *header,
            const u_char *packet);

    void initialize(connectors::Connector& connector, PCAPManager& pcapMgr, DaemonLog& daemonLog, string& pcapFilterString,
            string& pcapDeviceString, list<uint32_t>& ipBackSvcList, ProcessIdentifier *processConnIdentifier, ProcessIdentifier *processListenIdentifier, flows::FlowProcessManager *fpm) {
        connector_ = &connector;
        pcapMgr_ = &pcapMgr;
        log_ = &daemonLog;
        ipBackSvcList_ = &ipBackSvcList;
        pConnectingIdentifier_ = processConnIdentifier;
        pListeningIdentifier_ = processListenIdentifier;
        flowProcessManager_ = fpm;

        errorFBSYNThrottle = new Throttle(3, 30000);

        pcapMgr_->setup(pcapFilterString.c_str(), pcapDeviceString.c_str());

        startFlowsManager_.init();
        endFlowsManager_.init();
    }

    virtual bool haveYouSeenThisIPLAstMinute(const char *ipCString);
    virtual std::list<std::function<void (const struct timeval&)>> getTimedActionsList();

    virtual void endSniffing() {
        end = true;
        log_->info("END SNIFFING");
        pcapMgr_->endLoop();
        //finalize threads
        log_->info("END SNIFFING Loop");
    }

private:
    typedef struct buffer {
        uint8_t msg[MAX_MSG_LEN];
        struct pcap_pkthdr hdr;
        uint8_t status;
        uint16_t len;
    } msg_buffer_t;

    typedef struct event {
        //Caution: Do not change order of first 4 elements, coupled to skb_t
        uint16_t portSrc;
        uint16_t portDst;
        uint8_t ipSrc[IPV4_ADDR_LEN];
        uint8_t ipDst[IPV4_ADDR_LEN];
        char code[EVENT_CODE_SIZE + 1];
        uint32_t value;
        int32_t pid;
        common_evt_t cevt;
        void *extra;
    } event_t;


    struct skb_holder_t {
        skb_t *skb;
        bool retRequired;
    };
    struct eventTracker_t {
        uint32_t count;
        TriggerAlgorithm *triggerAlg;
    };

    enum EventDirection_t {FROM_INITIATOR = 0, FROM_DST = 1};
    enum ConnectionType_t {CONN_UNKNOWN = 0, CONN_TLS = 1, CONN_PLAIN_HTTP = 2, CONN_PLAIN_UNKNOWN = 3};
    enum ConnectionEndType_t {CONN_END_FIN = 0, CONN_END_TLS_ALERT = 1, CONN_END_RESET = 2};
    static constexpr const char MSG_BUFFER_STR[] = "MsgBuffer";
    static constexpr const char EVENT_STR[] = "Event";
    static constexpr const char SKB_HOLDER_STR[] = "SkbHolder";
    static const int LOCAL_NODE_IP_SRC = 0;
    static const int LOCAL_NODE_IP_DST = 1;
    static const int LOCAL_NODE_IP_THIRD = 2;
    static const int kMaxCountRepSyncFromInternet_ = 3;
    static const int kMaxCountConnKilledFromInternet_ = 3;
    static const int kMaxCountResetFromInternet_ = 3;
    static const int kMaxCountSSLFromInternet_ = 6;
    static const int kMaxCountStaleFromInternet_ = 3;
    bool end{false};

    objmem_manager::MemoryManager<msg_buffer_t, MSG_BUFFER_STR> *mMgrMsgBuffer_{nullptr};
    objmem_manager::MemoryManager<event_t, EVENT_STR> *mMgrEvent_{nullptr};
    objmem_manager::MemoryManager<skb_holder_t, SKB_HOLDER_STR> *mMgrSkbHolder_{nullptr};
    std::mutex qMutex_;

    Queue<msg_buffer_t> *msgQueue_{nullptr};
    FastQueue<event_t> *fastQueueEvt_{nullptr};
    FastQueue<event_t> *idProcessQueue_{nullptr};
    FastQueue<skb_holder_t> *fastQueueSkb_{nullptr};
    bool finalEmptyQ_{false};

    std::mutex waitMsgMutex;
    std::condition_variable waitMsgCond;
    bool waitingForMsg{false};
    std::thread *thr[MAX_NUM_THR];
    std::thread *thrProcessIdentifier_[NUM_PROCESS_IDENTIFIER_THR];
    std::thread *thrEvtProcessor_[MAX_EVT_PROCESSOR_THR];
    std::thread *thrSkbDumper_[MAX_SKB_DUMPER_THR];
    std::thread *thrSkblistProcessor_{nullptr};
    std::thread *thrPCAPLoop_{nullptr};

    int gSendCounter{0};
    connectors::Connector *connector_{nullptr};

    PCAPManager *pcapMgr_{nullptr};
    DaemonLog *log_{nullptr};

    uint32_t packetCounter_{0};
    std::map<uint32_t, map<uint16_t, eventTracker_t *>> resetSrcMap_;
    std::map<uint32_t, map<uint16_t, eventTracker_t *>> resetAfterFINMap_;
    uint32_t totalResetAfterFIN_{0};
    uint32_t totalResetSrc_{0};
    std::chrono::seconds lastTimeResetCheck_{0};

    Throttle *errorFBSYNThrottle{nullptr};
    ProcessIdentifier *pConnectingIdentifier_{nullptr};
    ProcessIdentifier *pListeningIdentifier_{nullptr};

    flows::StartFlowsManager startFlowsManager_;
    flows::EndFlowsManager endFlowsManager_;
    std::list<uint32_t> *ipBackSvcList_{nullptr};
    bool msgProcessorIsRunning_{false};
    uint16_t countResetFromInternet_{0};
    uint16_t countRepSyncFromInternet_{0};
    uint16_t countConnKilledFromInternet_{0};
    uint16_t countSSLFromInternet_{0};
    uint16_t countStaleFromInternet_{0};
    struct timeval lastTimeCounterReset_{0,0};
    uint16_t hoursToResetCounter_{HOURS_COUNTER_RESET};
    flows::FlowProcessManager *flowProcessManager_{nullptr};



    static void msgProcessorThr(PacketSniffer *ps, Queue<msg_buffer_t> *mq);
    static void processSkbListThread(PacketSniffer *ps);
    static void evtProcessorThr(PacketSniffer *ps, FastQueue<event_t> *eventQ);
    static void packetDumperProcessorThr(PacketSniffer *ps, FastQueue<skb_holder_t> *skbQ);
    static void processIdentifierThr(PacketSniffer *ps);
    static void PCAPLoopThr(PacketSniffer *ps);

    void cleanMsgQueue(Queue<msg_buffer_t> *mq);
    void processMessage(msg_buffer_t *msgBuf);

    int mainAgentThread();
    void processConnectingSkbList();
    void processEstablishedSkbList();
    uint8_t *createJSONMsg(uint8_t *data, event_t *eventPtr, uint32_t& offset, bool extraData = false);
    int processTCPEstablishedMessage(skb_t *usrSkb, struct timeval& timeStamp, uint8_t *ipSrc, uint16_t portSrc, uint32_t tcpDataLen);
    int enqueueEvent(skb_t *usrSkb, struct timeval& timeStamp,const char *code, uint32_t value, uint8_t quality, uint8_t direc = 0xFF);
    int enqueueEvent(event_t *eventPtr);
    int enqueueSkb(skb_t *usrSkb, bool retRequired = false);
    void cleanConnectingSkbList();
    void cleanEstablishedSkbList();
    void disposeSkbResources(skb_t *currentSkb);

    int processFlowEnd(skb_t *usrSkb, struct timeval& timestamp, ConnectionEndType_t endType, uint8_t direc);

    void populateEvent(event_t *eventPtr, skb_t *usrSkb, struct timeval& timeStamp, const char *code, uint32_t value, uint32_t quality) {
        memcpy(eventPtr->ipSrc, usrSkb->ipSrc, IPV4_ADDR_LEN);
        memcpy(eventPtr->ipDst, usrSkb->ipDst, IPV4_ADDR_LEN);
        eventPtr->portSrc = usrSkb->portSrc;
        eventPtr->portDst = usrSkb->portDst;
        memcpy(eventPtr->code, code, EVENT_CODE_SIZE + 1);
        eventPtr->value = value;
        eventPtr->pid = usrSkb->pid;
        eventPtr->cevt.initTimeStamp = timeStamp;
        eventPtr->cevt.latency1 = usrSkb->latency1;
        eventPtr->cevt.latency2 = usrSkb->latency2;
        eventPtr->cevt.quality = quality;
    }


    event_t *getNewEvent() {
        event_t *eventPtr = nullptr;
        try {
            log_->debug("Creating new event.\n");
            eventPtr = mMgrEvent_->createInstance();
            if (!eventPtr) {
                log_->error("Error: event not created.\n");
            }
        } catch(objmem_manager::MemoryManager<event_t, EVENT_STR>::MemoryMgrException& excep) {
            log_->warning("Exception creating new event. %s.\n", excep.getExceptionMsg().c_str());
        }

        return eventPtr;
    }

    int processFlowBegin(skb_t *usrSkb);

    //TODO: create memory reservation for this
    void cleanResetData() {
        for(auto& pair1 : resetAfterFINMap_) {
            for(auto& pair2 : resetAfterFINMap_[pair1.first]) {
                delete pair2.second->triggerAlg;
                delete pair2.second;
            }
            resetAfterFINMap_[pair1.first].clear();
        }
        resetAfterFINMap_.clear();
        for(auto& pair1 : resetSrcMap_) {
            for(auto& pair2 : resetSrcMap_[pair1.first]) {
                delete pair2.second->triggerAlg;
                delete pair2.second;
            }
            resetSrcMap_[pair1.first].clear();
        }
        resetSrcMap_.clear();
        totalResetSrc_ = 0;
        totalResetAfterFIN_ = 0;
    }
    int processRepeatedSync(skb_t *usrSkb, struct timeval& timeStamp) {
        // Only ask for KILLED - The socket could be NOT valid at this moment
        if (!IS_SKB_STATE_KILLED(usrSkb)) {
            if (Configuration::getInstance().incomingInternetConnections) {
                return enqueueEvent(usrSkb, timeStamp, CODE_TCP_SYN_RETRANS_STR, usrSkb->syncRetries, 1);
            } else {
                if (!Interface::isFromInternet(*((uint32_t *)usrSkb->ipSrc), *((uint32_t *)usrSkb->ipDst))) {
                    return enqueueEvent(usrSkb, timeStamp, CODE_TCP_SYN_RETRANS_STR, usrSkb->syncRetries, 1);
                } else if (countRepSyncFromInternet_ < kMaxCountRepSyncFromInternet_){
                    countRepSyncFromInternet_++;
                    return enqueueEvent(usrSkb, timeStamp, CODE_TCP_SYN_RETRANS_STR, usrSkb->syncRetries, 0);
                }
            }
        }
        return 0;
    }

    int processConnectingKilledNotification(skb_t *usrSkb) {
        // Not asking for killed. Assumption: it's not killed yet.
        struct timeval timeStamp;
        getTimestampNow(timeStamp);
        if (Configuration::getInstance().incomingInternetConnections) {
            return enqueueEvent(usrSkb, timeStamp, CODE_TCP_PARTIAL_CONNECTION_STR, 0, 1);
        } else {
            if (!Interface::isFromInternet(*((uint32_t *)usrSkb->ipSrc), *((uint32_t *)usrSkb->ipDst))) {
                return enqueueEvent(usrSkb, timeStamp, CODE_TCP_PARTIAL_CONNECTION_STR, 0, 1);
            } else if (countConnKilledFromInternet_ < kMaxCountConnKilledFromInternet_){
                countConnKilledFromInternet_++;
                return enqueueEvent(usrSkb, timeStamp, CODE_TCP_PARTIAL_CONNECTION_STR, 0, 0);
            } else {
                return 0;
            }
        }
    }

    bool isSSH(skb_t *usrSkb) {
        return (usrSkb->portDst == 22);
    }

    bool validateStaleEventFromInternet(skb_t *usrSkb) {
        if (isSSH(usrSkb)) {
            if (Configuration::getInstance().eventStaleSSHFromInternet) {
                return true;
            }
            return false;
        }
        return true;
    }

    int processStaleNotification(skb_t *usrSkb, const char *code) {
        struct timeval timeStamp;
        uint8_t quality;
        if (!Configuration::getInstance().incomingInternetConnections) {
            if (Interface::isFromInternet(*((uint32_t *)usrSkb->ipSrc), *((uint32_t *)usrSkb->ipDst))) {
                if (countStaleFromInternet_ < kMaxCountStaleFromInternet_) {
                    if (validateStaleEventFromInternet(usrSkb)) {
                        countStaleFromInternet_++;
                        getTimestampNow(timeStamp);
                        quality = 0;
                        enqueueEvent(usrSkb, timeStamp, code, 0, quality);
                        return 0;
                    } else {
                        return -1;
                    }
                } else {
                    return -1;
                }
            } else {
                getTimestampNow(timeStamp);
                quality = 1;
                enqueueEvent(usrSkb, timeStamp, code, 0, quality);
                return 0;
            }
        } else {
            getTimestampNow(timeStamp);
            quality = 1;
            enqueueEvent(usrSkb, timeStamp, code, 0, quality);
            return 0;
        }
    }

    int processStaleNotification(skb_t *usrSkb) {
        // Not asking for killed. Assumption: it's not killed yet.
        return processStaleNotification(usrSkb, CODE_TCP_ESTABLISHED_STALE_STR);
    }

    int processEstablishedKilledNotification(skb_t *usrSkb) {
        // Not asking for killed. Assumption: it's not killed yet.
        return processStaleNotification(usrSkb, CODE_TCP_ESTABLISHED_STALE2_STR);
    }

    //TODO: determine a way to delete the eventTracker_t and TriggerAlgorithm after some time
    int processReset(skb_t *usrSkb, struct timeval& timeStamp, uint8_t *ipSrc, uint16_t portSrc) {
        // Only ask for KILLED - The socket could be NOT valid at this moment
        int retValue = 0;
        if (!IS_SKB_STATE_KILLED(usrSkb)) {
            // I don't care about endianship, only uniqueness
            uint32_t ipAddr = *((uint32_t *)ipSrc);
            uint8_t direc;
            TriggerAlgorithm::eLBResult triggerRes;
            uint32_t eventCount;
            uint8_t quality = 1;

            //If status is already FIN1, don't send alert. This is OK.
            if (usrSkb->cStatus == FIN1) {
                return 1;
            }

            if (portSrc == usrSkb->portSrc && *((uint32_t *)usrSkb->ipSrc) == ipAddr) {
                direc = FROM_INITIATOR; //The one initiating the connection is sending RST
            } else {
                direc = FROM_DST; //The DST is sending RST
            }

            processFlowEnd(usrSkb, timeStamp, CONN_END_RESET, direc);

            if (!Configuration::getInstance().incomingInternetConnections) {
                if (Interface::isFromInternet(*((uint32_t *)usrSkb->ipSrc), *((uint32_t *)usrSkb->ipDst))) {
                    if (countResetFromInternet_ < kMaxCountResetFromInternet_){
                        quality = 0;
                    } else {
                        return 1;
                    }
                }
            }

            if (portSrc == usrSkb->portSrc && *((uint32_t *)usrSkb->ipSrc) == ipAddr) {
                if (Configuration::getInstance().NoHTTPClientResetEvent) {
                    if (IS_HTTPS(usrSkb->portDst) || IS_HTTP(usrSkb->portDst)) {
                        if (usrSkb->cStatus != SYN) {
                            //Do not send RESET sent by HTTP Browser unless configured to do so
                            return 1;
                        }
                    }
                }
            }

            if (usrSkb->cDeviation == FIN1_DATA) { //Data was sent/Rcv after RST
                //Since we do not report RESET after FIN, this case is not valid anymore
                //TODO: I'm not sure that we need to check against usrSkb->portDst or DST of reset message
                //Maybe we need to take into account the value of direc? Is it always the one opening the conn the one that sends the RST (direc == FROM_INITIATOR)?
                if (resetAfterFINMap_.find(ipAddr) == resetAfterFINMap_.end() ||
                        resetAfterFINMap_[ipAddr].find(usrSkb->portDst) == resetAfterFINMap_[ipAddr].end()) {
                    eventTracker_t *et = new eventTracker_t();
                    et->count = 1;
                    et->triggerAlg = new Throttle(6, 3600);
                    resetAfterFINMap_[ipAddr][usrSkb->portDst] = et;
                    totalResetAfterFIN_++;
                } else {
                    resetAfterFINMap_[ipAddr][usrSkb->portDst]->count++;
                }
                triggerRes = resetAfterFINMap_[ipAddr][usrSkb->portDst]->triggerAlg->executeOnEvent();
                eventCount = resetAfterFINMap_[ipAddr][usrSkb->portDst]->count;
            } else {
                //The typical case is somebody sending a SYN to a port where nobody is listening to: (usrSkb->cStatus == SYN)
                //But it also could be a service that always finishes with RST
                if (resetSrcMap_.find(ipAddr) == resetSrcMap_.end() ||
                        resetSrcMap_[ipAddr].find(portSrc) == resetSrcMap_[ipAddr].end()) {
                    eventTracker_t *et = new eventTracker_t();
                    et->count = 1;
                    et->triggerAlg = new ThrottleLogarithmic();
                    resetSrcMap_[ipAddr][portSrc] = et;
                    totalResetSrc_++;
                } else {
                    resetSrcMap_[ipAddr][portSrc]->count++;
                }
                triggerRes = resetSrcMap_[ipAddr][portSrc]->triggerAlg->executeOnEvent();
                eventCount = resetSrcMap_[ipAddr][portSrc]->count;
            }

            if (triggerRes == TriggerAlgorithm::LB_TRIGGER || triggerRes == TriggerAlgorithm::LB_TRIGGER_ABNORMAL) {
                if (quality == 0) {
                    //Only if the event is triggered we increase the counter
                    countResetFromInternet_++;
                }
                event_t *eventPtr = getNewEvent();
                if (eventPtr) {
                    const char *code = (usrSkb->cStatus == SYN) ? CODE_TCP_SYN_RESET_STR : CODE_TCP_RESET_STR;
                    if (triggerRes == TriggerAlgorithm::LB_TRIGGER_ABNORMAL) code = CODE_TCP_RESET_ABNORMAL_STR;

                    populateEvent(eventPtr, usrSkb, timeStamp, code,
                            eventCount, quality);
                    eventPtr->cevt.evtSrc = direc;

                    enqueueEvent(eventPtr);
                }
            } else {
                retValue = 1;
            }

            using namespace std::chrono;
            seconds secNow = duration_cast<seconds>(system_clock::now().time_since_epoch());
            system_clock::duration dur = secNow - lastTimeResetCheck_;
            if (std::chrono::duration_cast<std::chrono::seconds>(dur).count() > 7200) { //If 2hs have passed
                log_->info("Cleaning reset data structures after 2 hours");
                cleanResetData();
                lastTimeResetCheck_ = secNow;
            } else if (totalResetSrc_ >= 10000 || totalResetAfterFIN_ >= 10000){
                log_->info("Cleaning reset data structures for threshold reached, %d, %d", totalResetSrc_, totalResetAfterFIN_);
                cleanResetData();
                lastTimeResetCheck_ = secNow;
            }
        }
        return retValue;
    }

    bool isBackendSvc(skb_t *usrSkb) {
        uint32_t addr = (*((uint32_t *)usrSkb->ipDst));
        if (find(ipBackSvcList_->begin(), ipBackSvcList_->end(), addr) != ipBackSvcList_->end()) {
            return true;
        }
        return false;
    }

    int processFirstTLSMessage(skb_t *usrSkb, struct timeval& timeStamp, uint8_t *ipSrc, uint16_t portSrc) {
        if (!IS_SKB_STATE_KILLED(usrSkb)) {
            if (Configuration::getInstance().events_for_tls_connections && !isBackendSvc(usrSkb)) {
                enqueueEvent(usrSkb, timeStamp, CODE_TCP_IS_TLS_STR, 0, 1);
            }
            processTCPEstablishedMessage(usrSkb, timeStamp, ipSrc, portSrc, 0);
        }

        return 0;
    }

    inline void updateDataTo(skb_t *usrSkb, uint32_t tcpDataLen) {
            usrSkb->dataTo += tcpDataLen;
    }
    inline void updateDataFrom(skb_t *usrSkb, uint32_t tcpDataLen) {
            usrSkb->dataFrom += tcpDataLen;
    }

    void zeroProcessData(ProcessIdentifier::ProcessData &pd) {
        pd = {NO_PROCESS_PID, "?", "?", NO_PROCESS_PID, 0xFFFFFFFF, 0};
    }

    std::function<void (const struct timeval&)> getTimedAction();

};

#endif /* PACKETSNIFFER_H_ */
