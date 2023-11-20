/*
 * packetSniffer.cpp
 *
 *  Created on: Mar 30, 2020
 *      Author: rodolk
 */

#include "packetSniffer.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

#include <net/ethernet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <http/httpTypeMsg.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sched.h>
#include <time.h>

#include <thread>
#include <chrono>

#include "env.h"
#include "Connector.h"
#include "queue.h"
//#include "http_message.h"
#include "skb.h"
//#include "registration_mgmt.h"
#include "daemonLog.h"
#include "frameStoreHandler.h"
#include "TLSInterpreter.h"
#include "HTTPInterpreter.h"
#include "interface.h"
#include "processIdentifierLSOF.h"
#include "ipconst.h"
#include "Configuration.h"
//#define GDB_SRV

#define SKB_LIST_PROCESS_PERIOD_SEC 5
#define SKB_LIST_PROCESS_ESTABLISHED_PERIODS 6

#define MAX_SKB_PROCESS_SET 10
#define SKB_VALID_CNT_THR 0x0C //1 minute (12 x 5 secs)
#define SKB_RESEND_CNT_THR 2 //10 secs
#define KEEPALIVE_CNT_THR_PARTIAL_CONNETION 4
#define KEEPALIVE_CNT_THR_EST_STALE 6  //3 min
#define KEEPALIVE_CNT_THR_EST_KILL  20  //10 min
#define ORPHAN_CNT_THR 14

//#define IS_SKB_VALID_CNT_THR(skbarg) (SKB_VALID_CNT_VALUE(skbarg) == SKB_VALID_CNT_THR)
//#define IS_SKB_RESEND_CNT_THR(skbarg) (SKB_RESEND_CNT_VALUE(skbarg) == SKB_RESEND_CNT_THR)
//#define IS_SKB_ORPHAN_CNT_THR(skbarg) (SKB_ORPHAN_CNT_VALUE(skbarg) == ORPHAN_CNT_THR)

#define ETHER_DEFAULT_HDR_LEN 14

//Environment variables
std::map<std::string, std::string> gEnvVarsMap;
uint16_t gFollowPort = 0;


PacketSniffer::PacketSniffer() {
    using namespace std::chrono;
    lastTimeResetCheck_ = duration_cast<seconds>(system_clock::now().time_since_epoch());
    getTimestampNow(lastTimeCounterReset_);
}

PacketSniffer::~PacketSniffer() {
}


void PacketSniffer::processPCAPPacketCallback(u_char *args, const struct pcap_pkthdr *header,
        const u_char *packet)
{
    PacketSniffer *psInst = (PacketSniffer *)args;

    if (psInst->end) return;

    uint32_t msgLen = (header->caplen > MAX_MSG_LEN) ? MAX_MSG_LEN : header->caplen;
    msg_buffer_t *msgBufPtr;

#ifdef GDB_SRV
//        log_->debug("Index %d\n", ifr.ifr_ifindex);
    psInst->log_->debug("REQUEST RECEIVED: len %d:\n", msgLen);
#endif


    try {
        msgBufPtr = psInst->mMgrMsgBuffer_->createInstance();

        if (msgBufPtr->status == 0) {
            memcpy(msgBufPtr->msg, packet, msgLen);
            memcpy(&(msgBufPtr->hdr), header, sizeof(struct pcap_pkthdr));
            msgBufPtr->status = 1;
            msgBufPtr->len = msgLen;
            psInst->gSendCounter++;

            Queue<msg_buffer_t>::eQueueStatus result = psInst->msgQueue_->addElement(msgBufPtr);
            if (result == Queue<msg_buffer_t>::QUEUE_FULL) {
                psInst->log_->warning("Queue is full. Discarding packet.\n");
                msgBufPtr->status = 0;
                psInst->mMgrMsgBuffer_->returnInstance(msgBufPtr);
            }
            if (psInst->waitingForMsg) {
                psInst->log_->debug("Thread waiting for message. Notifying\n");
                psInst->waitMsgCond.notify_all();
            }
        } else {
            psInst->log_->error("Created msg buffer with status != 0. This is a code error. Discarding packet.\n");
            msgBufPtr->status = 0;
            psInst->mMgrMsgBuffer_->returnInstance(msgBufPtr);
        }
    } catch(objmem_manager::MemoryManager<msg_buffer_t, MSG_BUFFER_STR>::MemoryMgrException& excep) {
        psInst->log_->warning("Exception creating new msg buffer. %s\n", excep.getExceptionMsg().c_str());
        psInst->log_->warning("Discarding packet.\n");
    }

}




void PacketSniffer::runAgentThread(PacketSniffer *packetSnifferInst)
{
    int j;

    initializeSkb();
    FrameBuffer::initialize(NUM_FRAME_BUFFER);

    if (Configuration::getInstance().keepaliveThresholdEstablishedKilled == 0) {
        Configuration::getInstance().keepaliveThresholdEstablishedKilled = KEEPALIVE_CNT_THR_EST_KILL;
    }
    if (Configuration::getInstance().keepaliveThresholdStaleEstablished == 0) {
        Configuration::getInstance().keepaliveThresholdStaleEstablished = KEEPALIVE_CNT_THR_EST_STALE;
    }

    packetSnifferInst->msgQueue_ = new Queue<msg_buffer_t>(MAX_NUM_MSG_BUF * 2);
    packetSnifferInst->fastQueueEvt_ = new FastQueue<event_t>(MAX_NUM_EVT, MAX_NUM_EVT, 2);
    packetSnifferInst->idProcessQueue_ = new FastQueue<event_t>(5, 5, 1);

    packetSnifferInst->fastQueueSkb_ = new FastQueue<skb_holder_t>(MAX_NUM_SKB_HOLDER, MAX_NUM_SKB_HOLDER, 2);

    packetSnifferInst->mMgrMsgBuffer_ = new objmem_manager::MemoryManager<msg_buffer_t, MSG_BUFFER_STR>(
            MAX_NUM_MSG_BUF, MAX_NUM_MSG_BUF, 2);
    packetSnifferInst->mMgrEvent_ = new objmem_manager::MemoryManager<event_t, EVENT_STR>(
            MAX_NUM_EVT, MAX_NUM_EVT, 2);
    packetSnifferInst->mMgrSkbHolder_ = new objmem_manager::MemoryManager<skb_holder_t, SKB_HOLDER_STR>(
            MAX_NUM_SKB_HOLDER, MAX_NUM_SKB_HOLDER, 2);

    for(j=0; j < MAX_NUM_THR; j++) {
        packetSnifferInst->thr[j] = new std::thread(msgProcessorThr, packetSnifferInst,
                packetSnifferInst->msgQueue_);
    }

    packetSnifferInst->msgProcessorIsRunning_ = true;

    for(j=0; j < NUM_PROCESS_IDENTIFIER_THR; j++) {
        packetSnifferInst->thrProcessIdentifier_[j] = new std::thread(processIdentifierThr, packetSnifferInst);
    }

    for(j=0; j < MAX_EVT_PROCESSOR_THR; j++) {
        packetSnifferInst->thrEvtProcessor_[j] = new std::thread(evtProcessorThr, packetSnifferInst,
                packetSnifferInst->fastQueueEvt_);
    }

    for(j=0; j < MAX_SKB_DUMPER_THR; j++) {
        packetSnifferInst->thrSkbDumper_[j] = new std::thread(packetDumperProcessorThr, packetSnifferInst,
                packetSnifferInst->fastQueueSkb_);
    }

    packetSnifferInst->thrSkblistProcessor_ = new std::thread(processSkbListThread, packetSnifferInst);

    packetSnifferInst->pcapMgr_->openPCAP();
    std::cerr << "openPCAP called" << std::endl;
    //TODO: CUIDADO!!!!!!!! HAY UNA RACE CONDITION ENTRE ESTAS DOS LLAMADAS

    packetSnifferInst->thrPCAPLoop_ = new std::thread(PCAPLoopThr, packetSnifferInst);

    for(j=0; j < MAX_NUM_THR; j++) {
        packetSnifferInst->thr[j]->join();
        delete packetSnifferInst->thr[j];
    }

    packetSnifferInst->msgProcessorIsRunning_ = false;

    packetSnifferInst->thrSkblistProcessor_->join();
    delete packetSnifferInst->thrSkblistProcessor_;

    packetSnifferInst->finalEmptyQ_ = true;

    for(j=0; j < NUM_PROCESS_IDENTIFIER_THR; j++) {
        packetSnifferInst->thrProcessIdentifier_[j]->join();
        delete packetSnifferInst->thrProcessIdentifier_[j];
    }

    for(j=0; j < MAX_EVT_PROCESSOR_THR; j++) {
        packetSnifferInst->thrEvtProcessor_[j]->join();
        delete packetSnifferInst->thrEvtProcessor_[j];
    }
    for(j=0; j < MAX_SKB_DUMPER_THR; j++) {
        packetSnifferInst->thrSkbDumper_[j]->join();
        delete packetSnifferInst->thrSkbDumper_[j];
    }

    packetSnifferInst->pcapMgr_->cleanup();

    //Remove all messages from msgQueue_ because they are not removed with the destructor
    packetSnifferInst->cleanMsgQueue(packetSnifferInst->msgQueue_);

    delete packetSnifferInst->msgQueue_;
    delete packetSnifferInst->fastQueueSkb_;
    delete packetSnifferInst->fastQueueEvt_;
    delete packetSnifferInst->idProcessQueue_;

    delete packetSnifferInst->mMgrSkbHolder_;
    delete packetSnifferInst->mMgrEvent_;
    delete packetSnifferInst->mMgrMsgBuffer_;

    shutdownSkb();

    FrameBuffer::shutdown();
    //We call detach because PCAP loop can take a long time to return.
    if (packetSnifferInst->thrPCAPLoop_ && packetSnifferInst->thrPCAPLoop_->joinable()) {
        try {
            packetSnifferInst->thrPCAPLoop_->detach();
            packetSnifferInst->log_->info("PCAP Loop thread detached ... bye ... bye\n");
            delete packetSnifferInst->thrPCAPLoop_;
        } catch (...) {
            packetSnifferInst->log_->info("PCAP Loop thread already completed\n");
        }
    }

    packetSnifferInst->log_->info("Main packet sniffer thread ended.\n");
}

extern skb_t *listConnectingSkb;
extern skb_t *listEstablishedSkb;



void PacketSniffer::cleanMsgQueue(Queue<msg_buffer_t> *mq) {
    msg_buffer_t *msgBuf;
    qMutex_.lock();

    msgBuf = msgQueue_->getNextElement();
    while(msgBuf != nullptr) {
        msgBuf->status = 0;
        mMgrMsgBuffer_->returnInstance(msgBuf);
        msgBuf = 0;
        msgBuf = msgQueue_->getNextElement();
    }

    qMutex_.unlock();
}
void PacketSniffer::msgProcessorThr(PacketSniffer *ps, Queue<msg_buffer_t> *mq)
{
    PacketSniffer *packetSnifferInst = ps;
    msg_buffer_t *msgBuf;
    Queue<msg_buffer_t> *msgQueue_ = mq;
    int waitState = 0;

    while(!packetSnifferInst->end) {
        packetSnifferInst->qMutex_.lock();

        msgBuf = msgQueue_->getNextElement();

        packetSnifferInst->qMutex_.unlock();

        if (msgBuf) {
            waitState = 0;
            packetSnifferInst->processMessage(msgBuf);
            packetSnifferInst->log_->debug("Finished processing message -----------\n");
            msgBuf->status = 0;
            packetSnifferInst->mMgrMsgBuffer_->returnInstance(msgBuf);
            msgBuf = 0;
            //test = 0;
        } else if (!packetSnifferInst->end) {
            //if (packetCunter_ > 2000 && test++ < 10) log_->info("MSGs dequeued received: %d\n", packetCounter_);
            /*
             * We know there is a race condition setting and checking packetSnifferInst->waitingForMsg
             * but we don't care. The maximum problem in case of race condition realization is that our
             * thread may wait 1 or 5 seconds to process the just coming message.
             * But normal cases we are always faster because we are not using a mutex and this implies
             * no system call.
             */
            packetSnifferInst->waitingForMsg = true;
            if (waitState == 0) {
                packetSnifferInst->log_->debug("No more messages. Going to sleep 1\n");
                std::unique_lock<std::mutex> lck(packetSnifferInst->waitMsgMutex);
                packetSnifferInst->waitMsgCond.wait_for(lck, std::chrono::seconds(1));
                packetSnifferInst->log_->debug("Woke up 1\n");
                waitState = 1;
            } else {
                if (waitState == 1) {
                    packetSnifferInst->log_->debug("No more messages. Going to sleep 5\n");
                    std::unique_lock<std::mutex> lck(packetSnifferInst->waitMsgMutex);
                    packetSnifferInst->waitMsgCond.wait_for(lck, std::chrono::seconds(5));
                    packetSnifferInst->log_->debug("Woke up 5\n");
                }
            }
            packetSnifferInst->waitingForMsg = false;
        }
    }
    packetSnifferInst->log_->info("FINISHING msgProcessorThr\n");
}


void PacketSniffer::processMessage(msg_buffer_t *msgBuf) {
    uint8_t hwHdrLen = ETHER_DEFAULT_HDR_LEN;
    uint8_t ipHdrLenW;
    uint16_t tcpIdx;
    uint16_t tcpHdrLen;
    skb_t auxSkb;
    skb_t *usrSkbfound;
    skb_t *currSkb;
    uint16_t tcpMsgLen;
    uint16_t datagramLen;
    FrameStoreHandler *frameStoreHandler = FrameStoreHandler::getInstance();

    packetCounter_++;

    //log_->info("LENGTH READ: %u\n", length);
#ifdef GDB_SRV
    for(j=0; j<hwHdrLen;j++)
        printf("%2.2X-",(unsigned char)msgBuf->msg[j]);
        //log_->debug("%2.2X-",(unsigned char)msgBuf->msg[j]);
    log_->debug("\nIP HDR\n");

    for(j=0; j<20;j++)
        printf("%2.2X-",(unsigned char)msgBuf->msg[j+14]);
    //log_->debug("%2.2X-",(unsigned char)msgBuf->msg[j+14]);
    log_->debug("\nTCP HDR:\n");

    for(j=0; j<20;j++)
        printf("%2.2X-",(unsigned char)msgBuf->msg[j+34]);
    //log_->debug("%2.2X-",(unsigned char)msgBuf->msg[j+34]);
    log_->debug("\n");

    for(j=0; j<20;j++)
        log_->debug("%2.2X-",(unsigned char)msgBuf->msg[j+54]);
    log_->debug("\n");
#endif
    ipHdrLenW = msgBuf->msg[14] & 0x0F;

    tcpIdx = hwHdrLen + (ipHdrLenW * 4);
    datagramLen = ntohs(*((uint16_t *)&msgBuf->msg[16]));
    tcpMsgLen = datagramLen - (ipHdrLenW * 4);

    tcpHdrLen = ((msgBuf->msg[tcpIdx + 12] & 0xF0) >> 4) * 4;



/*            if (tcpMsgLen >= 20)
    {
        tcpHdrLen = ((buff[tcpIdx + 12] & 0xF0) >> 4) * 4;

        if (tcpMsgLen - tcpHdrLen > 50)
        {
            idx = getPayloadIndex(buff + tcpIdx + tcpHdrLen, (uint16_t)(tcpMsgLen - tcpHdrLen)) //(tcpMsgLen - tcpHdrLen) always > 0
        }
    }
*/
    auxSkb.portSrc = ntohs(*((uint16_t *)&msgBuf->msg[tcpIdx]));
    auxSkb.portDst = ntohs(*((uint16_t *)&msgBuf->msg[tcpIdx + 2]));
    memcpy(auxSkb.ipSrc, &msgBuf->msg[26], 4);
    memcpy(auxSkb.ipDst, &msgBuf->msg[30], 4);

#ifdef GDB_SRV
    log_->debug("IP src addr: %1.1d.%1.1d.%1.1d.%1.1d\n", auxSkb.ipSrc[0], auxSkb.ipSrc[1], auxSkb.ipSrc[2], auxSkb.ipSrc[3]);
    log_->debug("IP dst addr: %1.1d.%1.1d.%1.1d.%1.1d\n", auxSkb.ipDst[0], auxSkb.ipDst[1], auxSkb.ipDst[2], auxSkb.ipDst[3]);

    log_->debug("IP Header Len: %d\n", ipHdrLenW * 4);
    log_->debug("Datagram Len: %d\n", datagramLen);
    log_->debug("TCP msg Len: %d\n", tcpMsgLen);
    log_->debug("Src port: %d - Dst port: %d\n", auxSkb.portSrc, auxSkb.portDst);
#endif

    if (msgBuf->msg[47] & SYN_FLAG) {
#ifdef GDB_SRV
        log_->debug("SYN msg received\n");
#endif
        usrSkbfound = skbLookup(&auxSkb);
        if (usrSkbfound == NULL) {
            if (!(msgBuf->msg[47] & ACK_FLAG)) {
#ifdef GDB_SRV
                log_->debug("New connection SYN\n");
#endif
                currSkb = get_new_skb();

                if (currSkb) {
                    // skb_t#dep: we rely on ports being the first 2 fields in skb_t
                    memcpy((void *)currSkb, (void *)&auxSkb, SIZE_OF_IP_PORT);

                    /*
                     * After we insert the new skb_t calling addNewSkb, the skb_t can be processed in function processNxtSkbList.
                     * So skb_t must be configured before adding it.
                     * No need to synchronize access until the new skb is added to the list of used skb_t's.
                     */
                    currSkb->cStatus = SYN;

                    RESET_STATE(currSkb);
                    RESET_KEEPALIVE_CNT_MASK(currSkb);
                    currSkb->syncRetries = 0;
                    currSkb->initialTime = msgBuf->hdr.ts;
                    currSkb->origPortSrc = currSkb->portSrc;
                    currSkb->origPortDst = currSkb->portDst;
                    currSkb->pid = -1;
                    memcpy(currSkb->origIpSrc, currSkb->ipSrc, IPV4_ADDR_LEN);
                    processFlowBegin(currSkb);

                    try {
                        frameStoreHandler->initializeFrameBuffer(currSkb, SKB_MAX_COUNT_FB);
                        frameStoreHandler->storeFrame(msgBuf->msg, msgBuf->len, &(msgBuf->hdr), currSkb);
                    } catch (FrameBuffer::AllocException& except) {
                        currSkb->errorFrameBuffer = 1;
                        if (errorFBSYNThrottle->executeOnEvent() == TriggerAlgorithm::LB_TRIGGER) {
                            log_->error("Error processing connection:\nIP src: %1.1d.%1.1d.%1.1d.%1.1d\nIP dst: %1.1d.%1.1d.%1.1d.%1.1d\nPort src: %d\nPort dst: %d\nCould not reserve any buffer for first SYN connection\n%s",
                                    currSkb->origIpSrc[0], currSkb->origIpSrc[1], currSkb->origIpSrc[2], currSkb->origIpSrc[3],
                                    currSkb->ipDst[0], currSkb->ipDst[1], currSkb->ipDst[2], currSkb->ipDst[3],
                                    currSkb->portSrc, currSkb->portDst,
                                    except.getExceptionMsg().c_str());
                        }
                    }
                    addNewSkb(currSkb);
                } else {
                    log_->error("CRITICAL ERROR: did not get a new SKB for new connection-----------\n\n");
                }
            } else {
                log_->debug("received SYN/ACK for non-initiated connection\n");
            }
        } else if (!(msgBuf->msg[47] & ACK_FLAG)) {

#ifdef GDB_SRV
            log_->debug("received SYN repeated\n");
#endif
            pthread_mutex_lock(&usrSkbfound->skbmutex);
            if (!IS_SKB_STATE_KILLED(usrSkbfound) && !IS_SKB_DUMPING(usrSkbfound)) {
                if (usrSkbfound->cStatus == SYN) {
                    struct timeval timeStamp = msgBuf->hdr.ts;
                    if (!usrSkbfound->errorFrameBuffer) {
                        try {
                            frameStoreHandler->storeFrame(msgBuf->msg, msgBuf->len, &(msgBuf->hdr), usrSkbfound);
                        } catch (FrameBuffer::AllocException& except) {
                            usrSkbfound->errorFrameBuffer = 1;
                            if (usrSkbfound->origIpSrc[0] == usrSkbfound->ipSrc[0] && usrSkbfound->origIpSrc[1] == usrSkbfound->ipSrc[1] && usrSkbfound->origIpSrc[2] == usrSkbfound->ipSrc[2] && usrSkbfound->origIpSrc[3] == usrSkbfound->ipSrc[3]) {
                                log_->error("Error processing connection:\nIP src: %1.1d.%1.1d.%1.1d.%1.1d\nIP dst: %1.1d.%1.1d.%1.1d.%1.1d\nPort src: %d\nPort dst: %d\n %s",
                                        usrSkbfound->origIpSrc[0], usrSkbfound->origIpSrc[1], usrSkbfound->origIpSrc[2], usrSkbfound->origIpSrc[3],
                                        usrSkbfound->ipDst[0], usrSkbfound->ipDst[1], usrSkbfound->ipDst[2], usrSkbfound->ipDst[3],
                                        usrSkbfound->portSrc, usrSkbfound->portDst,
                                        except.getExceptionMsg().c_str());
                            } else {
                                log_->error("Error processing connection:\nIP src: %1.1d.%1.1d.%1.1d.%1.1d\nIP dst: %1.1d.%1.1d.%1.1d.%1.1d\nPort src: %d\nPort dst: %d\n %s",
                                        usrSkbfound->origIpSrc[0], usrSkbfound->origIpSrc[1], usrSkbfound->origIpSrc[2], usrSkbfound->origIpSrc[3],
                                        usrSkbfound->ipSrc[0], usrSkbfound->ipSrc[1], usrSkbfound->ipSrc[2], usrSkbfound->ipSrc[3],
                                        usrSkbfound->portDst, usrSkbfound->portSrc,
                                        except.getExceptionMsg().c_str());
                            }
                        }
                    }
                    usrSkbfound->syncRetries++;
                    //We only process retries 1, 2, 3, 6 (close to 10 secs), and retry 11 (after 10 min)
                    if (usrSkbfound->syncRetries < 4 || usrSkbfound->syncRetries == 6 || usrSkbfound->syncRetries == 11) {
                        processRepeatedSync(usrSkbfound, timeStamp);
                    }
                }
            }
            pthread_mutex_unlock(&usrSkbfound->skbmutex);
            returnSkb(usrSkbfound);
        } else { //It's SYN-ACK
            pthread_mutex_lock(&usrSkbfound->skbmutex);
            if (!IS_SKB_STATE_KILLED(usrSkbfound) && !IS_SKB_DUMPING(usrSkbfound)) {
                if (usrSkbfound->cStatus == SYN) {
                    usrSkbfound->cStatus = SYN_ACK;
                    calcLatency(usrSkbfound, &(msgBuf->hdr.ts));
                    if (!usrSkbfound->errorFrameBuffer) {
                        if (gFollowPort != 0 && (usrSkbfound->portDst == gFollowPort || usrSkbfound->portSrc == gFollowPort)) {
                            SET_MARKED_FOR_DUMP(usrSkbfound);
                            addMarkedForDump(usrSkbfound);
                        }
                        try {
                            frameStoreHandler->storeFrame(msgBuf->msg, msgBuf->len, &(msgBuf->hdr), usrSkbfound);
                        } catch (FrameBuffer::AllocException& except) {
                            usrSkbfound->errorFrameBuffer = 1;
                            if (usrSkbfound->origIpSrc[0] == usrSkbfound->ipSrc[0] && usrSkbfound->origIpSrc[1] == usrSkbfound->ipSrc[1] && usrSkbfound->origIpSrc[2] == usrSkbfound->ipSrc[2] && usrSkbfound->origIpSrc[3] == usrSkbfound->ipSrc[3]) {
                                log_->error("Error processing connection:\nIP src: %1.1d.%1.1d.%1.1d.%1.1d\nIP dst: %1.1d.%1.1d.%1.1d.%1.1d\nPort src: %d\nPort dst: %d\n %s",
                                        usrSkbfound->origIpSrc[0], usrSkbfound->origIpSrc[1], usrSkbfound->origIpSrc[2], usrSkbfound->origIpSrc[3],
                                        usrSkbfound->ipDst[0], usrSkbfound->ipDst[1], usrSkbfound->ipDst[2], usrSkbfound->ipDst[3],
                                        usrSkbfound->portSrc, usrSkbfound->portDst,
                                        except.getExceptionMsg().c_str());
                            } else {
                                log_->error("Error processing connection:\nIP src: %1.1d.%1.1d.%1.1d.%1.1d\nIP dst: %1.1d.%1.1d.%1.1d.%1.1d\nPort src: %d\nPort dst: %d\n %s",
                                        usrSkbfound->origIpSrc[0], usrSkbfound->origIpSrc[1], usrSkbfound->origIpSrc[2], usrSkbfound->origIpSrc[3],
                                        usrSkbfound->ipSrc[0], usrSkbfound->ipSrc[1], usrSkbfound->ipSrc[2], usrSkbfound->ipSrc[3],
                                        usrSkbfound->portDst, usrSkbfound->portSrc,
                                        except.getExceptionMsg().c_str());
                            }
                        }
                    }
                }
            }
            pthread_mutex_unlock(&usrSkbfound->skbmutex);
            returnSkb(usrSkbfound);
        }
    } else if (msgBuf->msg[47] & RST_FLAG) {       //No SYN flag
#ifdef GDB_SRV
        log_->debug("RST msg received\n");
#endif
        usrSkbfound = skbLookup(&auxSkb);
        if (usrSkbfound != NULL) {
            pthread_mutex_lock(&usrSkbfound->skbmutex);

            //log_->info("\n\n SEQ: %d\n\n", usrSkbfound->registeredSequence);
//            if (!IS_SKB_STATE_KILLED(usrSkbfound) && IS_SKB_STATE_VALID(usrSkbfound))
            if (!IS_SKB_STATE_KILLED(usrSkbfound) && !IS_SKB_DUMPING(usrSkbfound)) {
                int procResetRes;
                struct timeval timeStamp = msgBuf->hdr.ts;
                RESET_KEEPALIVE_CNT_MASK(usrSkbfound);
                if (!usrSkbfound->errorFrameBuffer) {
                    try {
                        frameStoreHandler->storeFrame(msgBuf->msg, msgBuf->len, &(msgBuf->hdr), usrSkbfound);
                    } catch (FrameBuffer::AllocException& except) {
                        usrSkbfound->errorFrameBuffer = 1;
                        if (usrSkbfound->origIpSrc[0] == usrSkbfound->ipSrc[0] && usrSkbfound->origIpSrc[1] == usrSkbfound->ipSrc[1] && usrSkbfound->origIpSrc[2] == usrSkbfound->ipSrc[2] && usrSkbfound->origIpSrc[3] == usrSkbfound->ipSrc[3]) {
                            log_->error("Error processing connection:\nIP src: %1.1d.%1.1d.%1.1d.%1.1d\nIP dst: %1.1d.%1.1d.%1.1d.%1.1d\nPort src: %d\nPort dst: %d\n %s",
                                    usrSkbfound->origIpSrc[0], usrSkbfound->origIpSrc[1], usrSkbfound->origIpSrc[2], usrSkbfound->origIpSrc[3],
                                    usrSkbfound->ipDst[0], usrSkbfound->ipDst[1], usrSkbfound->ipDst[2], usrSkbfound->ipDst[3],
                                    usrSkbfound->portSrc, usrSkbfound->portDst,
                                    except.getExceptionMsg().c_str());
                        } else {
                            log_->error("Error processing connection:\nIP src: %1.1d.%1.1d.%1.1d.%1.1d\nIP dst: %1.1d.%1.1d.%1.1d.%1.1d\nPort src: %d\nPort dst: %d\n %s",
                                    usrSkbfound->origIpSrc[0], usrSkbfound->origIpSrc[1], usrSkbfound->origIpSrc[2], usrSkbfound->origIpSrc[3],
                                    usrSkbfound->ipSrc[0], usrSkbfound->ipSrc[1], usrSkbfound->ipSrc[2], usrSkbfound->ipSrc[3],
                                    usrSkbfound->portDst, usrSkbfound->portSrc,
                                    except.getExceptionMsg().c_str());
                        }
                    }
                }
                procResetRes = processReset(usrSkbfound, timeStamp, auxSkb.ipSrc, auxSkb.portSrc);
                //TODO: errorFrameBuffer?
                usrSkbfound->cStatus = CLOSED;
                SET_SKB_STATE_KILLED(usrSkbfound);
                if (procResetRes == 0) {
                    //Set SKB_SKB_DUMP_PENDING for list processing thread to send for dump
                    SET_SKB_DUMP_PENDING(usrSkbfound);
                }
                pthread_mutex_unlock(&usrSkbfound->skbmutex);
                returnSkb(usrSkbfound);

//Todo: If we track lastacked we can add this check
//                int resRSTSEQ = checkRSTSEQ(usrSkbfound, msgBuf->msg, tcpMsgLen, tcpIdx);
            } else {
                pthread_mutex_unlock(&usrSkbfound->skbmutex);
                returnSkb(usrSkbfound);
            }
        }
        else {
            //log_->debug("received RST from wrong src\n");
        }
    }
    else if (msgBuf->msg[47] & FIN_FLAG) {
        log_->debug("FIN msg received\n");

        //A normal FIN doesn't require any further action or report. It's just normal

        usrSkbfound = skbLookup(&auxSkb);

        if (usrSkbfound != NULL) {
            pthread_mutex_lock(&usrSkbfound->skbmutex);
            if (!IS_SKB_STATE_KILLED(usrSkbfound) && !IS_SKB_DUMPING(usrSkbfound)) {
                RESET_KEEPALIVE_CNT_MASK(usrSkbfound);
                if (!usrSkbfound->errorFrameBuffer) {
                    try {
                        frameStoreHandler->storeFrame(msgBuf->msg, msgBuf->len, &(msgBuf->hdr), usrSkbfound);
                    } catch (FrameBuffer::AllocException& except) {
                        usrSkbfound->errorFrameBuffer = 1;
                        if (usrSkbfound->origIpSrc[0] == usrSkbfound->ipSrc[0] && usrSkbfound->origIpSrc[1] == usrSkbfound->ipSrc[1] && usrSkbfound->origIpSrc[2] == usrSkbfound->ipSrc[2] && usrSkbfound->origIpSrc[3] == usrSkbfound->ipSrc[3]) {
                            log_->error("Error processing connection:\nIP src: %1.1d.%1.1d.%1.1d.%1.1d\nIP dst: %1.1d.%1.1d.%1.1d.%1.1d\nPort src: %d\nPort dst: %d\n %s",
                                    usrSkbfound->origIpSrc[0], usrSkbfound->origIpSrc[1], usrSkbfound->origIpSrc[2], usrSkbfound->origIpSrc[3],
                                    usrSkbfound->ipDst[0], usrSkbfound->ipDst[1], usrSkbfound->ipDst[2], usrSkbfound->ipDst[3],
                                    usrSkbfound->portSrc, usrSkbfound->portDst,
                                    except.getExceptionMsg().c_str());
                        } else {
                            log_->error("Error processing connection:\nIP src: %1.1d.%1.1d.%1.1d.%1.1d\nIP dst: %1.1d.%1.1d.%1.1d.%1.1d\nPort src: %d\nPort dst: %d\n %s",
                                    usrSkbfound->origIpSrc[0], usrSkbfound->origIpSrc[1], usrSkbfound->origIpSrc[2], usrSkbfound->origIpSrc[3],
                                    usrSkbfound->ipSrc[0], usrSkbfound->ipSrc[1], usrSkbfound->ipSrc[2], usrSkbfound->ipSrc[3],
                                    usrSkbfound->portDst, usrSkbfound->portSrc,
                                    except.getExceptionMsg().c_str());
                        }
                    }
                }

                if (usrSkbfound->cStatus == FIN1) {
                    usrSkbfound->cStatus = CLOSED;
                    SET_SKB_STATE_KILLED(usrSkbfound);
                } else {
                    usrSkbfound->cStatus = FIN1;
                    if (auxSkb.portSrc == usrSkbfound->portSrc && *((uint32_t *)usrSkbfound->ipSrc) == *((uint32_t *)auxSkb.ipSrc)) {
                        processFlowEnd(usrSkbfound, msgBuf->hdr.ts, CONN_END_FIN, FROM_INITIATOR);
                    } else {
                        processFlowEnd(usrSkbfound, msgBuf->hdr.ts, CONN_END_FIN, FROM_DST);
                    }

                }
            }
            pthread_mutex_unlock(&usrSkbfound->skbmutex);
            returnSkb(usrSkbfound);
        }
        else {
            //log_->debug("received FIN from wrong src\n");
        }
    }
    else
    {
#ifdef GDB_SRV
        log_->debug("Est TCP - msg received\n");
#endif
        usrSkbfound = skbLookup(&auxSkb);
        if (usrSkbfound != NULL) {
            pthread_mutex_lock(&usrSkbfound->skbmutex);

//            if (!IS_SKB_STATE_KILLED(usrSkbfound) && IS_SKB_STATE_VALID(usrSkbfound))
            if (!IS_SKB_STATE_KILLED(usrSkbfound) && !IS_SKB_DUMPING(usrSkbfound)) {
                RESET_KEEPALIVE_CNT_MASK(usrSkbfound);
                if (usrSkbfound->cStatus == ESTABLISHED) {
                    if (!usrSkbfound->errorFrameBuffer) {
                        struct timeval timeStamp = msgBuf->hdr.ts;
                        try {
                            frameStoreHandler->storeFrame(msgBuf->msg, msgBuf->len, &(msgBuf->hdr), usrSkbfound);
                            if (msgBuf->hdr.len > msgBuf->len) {
                                SET_DO_NOT_PARSE(usrSkbfound);
                            }
                            processTCPEstablishedMessage(usrSkbfound, timeStamp, auxSkb.ipSrc, auxSkb.portSrc, tcpMsgLen - tcpHdrLen);
                        } catch (FrameBuffer::AllocException& except) {
                            usrSkbfound->errorFrameBuffer = 1;
                            if (usrSkbfound->origIpSrc[0] == usrSkbfound->ipSrc[0] && usrSkbfound->origIpSrc[1] == usrSkbfound->ipSrc[1] && usrSkbfound->origIpSrc[2] == usrSkbfound->ipSrc[2] && usrSkbfound->origIpSrc[3] == usrSkbfound->ipSrc[3]) {
                                log_->error("Error processing connection:\nIP src: %1.1d.%1.1d.%1.1d.%1.1d\nIP dst: %1.1d.%1.1d.%1.1d.%1.1d\nPort src: %d\nPort dst: %d\n %s",
                                        usrSkbfound->origIpSrc[0], usrSkbfound->origIpSrc[1], usrSkbfound->origIpSrc[2], usrSkbfound->origIpSrc[3],
                                        usrSkbfound->ipDst[0], usrSkbfound->ipDst[1], usrSkbfound->ipDst[2], usrSkbfound->ipDst[3],
                                        usrSkbfound->portSrc, usrSkbfound->portDst,
                                        except.getExceptionMsg().c_str());
                            } else {
                                log_->error("Error processing connection:\nIP src: %1.1d.%1.1d.%1.1d.%1.1d\nIP dst: %1.1d.%1.1d.%1.1d.%1.1d\nPort src: %d\nPort dst: %d\n %s",
                                        usrSkbfound->origIpSrc[0], usrSkbfound->origIpSrc[1], usrSkbfound->origIpSrc[2], usrSkbfound->origIpSrc[3],
                                        usrSkbfound->ipSrc[0], usrSkbfound->ipSrc[1], usrSkbfound->ipSrc[2], usrSkbfound->ipSrc[3],
                                        usrSkbfound->portDst, usrSkbfound->portSrc,
                                        except.getExceptionMsg().c_str());
                            }
                        }
                    }
                } else if (usrSkbfound->cStatus == SYN_ACK && (msgBuf->msg[47] & ACK_FLAG)) {
                    usrSkbfound->cStatus = LAST_HSHAKE_ACK;
                    calcLatency(usrSkbfound, &(msgBuf->hdr.ts));
                    if (!usrSkbfound->errorFrameBuffer) {
                        try {
                            frameStoreHandler->storeFrame(msgBuf->msg, msgBuf->len, &(msgBuf->hdr), usrSkbfound);
                        } catch (FrameBuffer::AllocException& except) {
                            usrSkbfound->errorFrameBuffer = 1;
                            if (usrSkbfound->origIpSrc[0] == usrSkbfound->ipSrc[0] && usrSkbfound->origIpSrc[1] == usrSkbfound->ipSrc[1] && usrSkbfound->origIpSrc[2] == usrSkbfound->ipSrc[2] && usrSkbfound->origIpSrc[3] == usrSkbfound->ipSrc[3]) {
                                log_->error("Error processing connection:\nIP src: %1.1d.%1.1d.%1.1d.%1.1d\nIP dst: %1.1d.%1.1d.%1.1d.%1.1d\nPort src: %d\nPort dst: %d\n %s",
                                        usrSkbfound->origIpSrc[0], usrSkbfound->origIpSrc[1], usrSkbfound->origIpSrc[2], usrSkbfound->origIpSrc[3],
                                        usrSkbfound->ipDst[0], usrSkbfound->ipDst[1], usrSkbfound->ipDst[2], usrSkbfound->ipDst[3],
                                        usrSkbfound->portSrc, usrSkbfound->portDst,
                                        except.getExceptionMsg().c_str());
                            } else {
                                log_->error("Error processing connection:\nIP src: %1.1d.%1.1d.%1.1d.%1.1d\nIP dst: %1.1d.%1.1d.%1.1d.%1.1d\nPort src: %d\nPort dst: %d\n %s",
                                        usrSkbfound->origIpSrc[0], usrSkbfound->origIpSrc[1], usrSkbfound->origIpSrc[2], usrSkbfound->origIpSrc[3],
                                        usrSkbfound->ipSrc[0], usrSkbfound->ipSrc[1], usrSkbfound->ipSrc[2], usrSkbfound->ipSrc[3],
                                        usrSkbfound->portDst, usrSkbfound->portSrc,
                                        except.getExceptionMsg().c_str());
                            }
                        }
                    }
                } else if (usrSkbfound->cStatus == LAST_HSHAKE_ACK) {
                    usrSkbfound->cStatus = ESTABLISHED;
                    struct timeval timeStamp = msgBuf->hdr.ts;
                    if (!usrSkbfound->errorFrameBuffer) {
                        try {
                            frameStoreHandler->storeFrame(msgBuf->msg, msgBuf->len, &(msgBuf->hdr), usrSkbfound);
                            //This isn't a memory leak. usrSkbfound will point to the TLSInterpreter
                            TLSInterpreter *tlsInter = new TLSInterpreter(usrSkbfound, tcpIdx + tcpHdrLen);

                            tlsInter->checkTLS();

                            if (usrSkbfound->isTLS == 1) {
                                processFirstTLSMessage(usrSkbfound, timeStamp, auxSkb.ipSrc, auxSkb.portSrc);
                            } else {
                                HTTPInterpreter *httpInter = new HTTPInterpreter(usrSkbfound, tcpIdx + tcpHdrLen);
                                httpInter->checkHTTP();
                                if (msgBuf->hdr.len > msgBuf->len) {
                                    SET_DO_NOT_PARSE(usrSkbfound);
                                }
                                processTCPEstablishedMessage(usrSkbfound, timeStamp, auxSkb.ipSrc, auxSkb.portSrc, tcpMsgLen - tcpHdrLen);
                            }
                        } catch (FrameBuffer::AllocException& except) {
                            usrSkbfound->errorFrameBuffer = 1;
                            if (usrSkbfound->origIpSrc[0] == usrSkbfound->ipSrc[0] && usrSkbfound->origIpSrc[1] == usrSkbfound->ipSrc[1] && usrSkbfound->origIpSrc[2] == usrSkbfound->ipSrc[2] && usrSkbfound->origIpSrc[3] == usrSkbfound->ipSrc[3]) {
                                log_->error("Error processing connection:\nIP src: %1.1d.%1.1d.%1.1d.%1.1d\nIP dst: %1.1d.%1.1d.%1.1d.%1.1d\nPort src: %d\nPort dst: %d\n %s",
                                        usrSkbfound->origIpSrc[0], usrSkbfound->origIpSrc[1], usrSkbfound->origIpSrc[2], usrSkbfound->origIpSrc[3],
                                        usrSkbfound->ipDst[0], usrSkbfound->ipDst[1], usrSkbfound->ipDst[2], usrSkbfound->ipDst[3],
                                        usrSkbfound->portSrc, usrSkbfound->portDst,
                                        except.getExceptionMsg().c_str());
                            } else {
                                log_->error("Error processing connection:\nIP src: %1.1d.%1.1d.%1.1d.%1.1d\nIP dst: %1.1d.%1.1d.%1.1d.%1.1d\nPort src: %d\nPort dst: %d\n %s",
                                        usrSkbfound->origIpSrc[0], usrSkbfound->origIpSrc[1], usrSkbfound->origIpSrc[2], usrSkbfound->origIpSrc[3],
                                        usrSkbfound->ipSrc[0], usrSkbfound->ipSrc[1], usrSkbfound->ipSrc[2], usrSkbfound->ipSrc[3],
                                        usrSkbfound->portDst, usrSkbfound->portSrc,
                                        except.getExceptionMsg().c_str());
                            }
                        }
                    }
                } else if (usrSkbfound->cStatus == FIN1) {
                    usrSkbfound->cDeviation = FIN1_DATA;
                    if (!usrSkbfound->errorFrameBuffer) {
                        try {
                            frameStoreHandler->storeFrame(msgBuf->msg, msgBuf->len, &(msgBuf->hdr), usrSkbfound);
                        } catch (FrameBuffer::AllocException& except) {
                            usrSkbfound->errorFrameBuffer = 1;
                            if (usrSkbfound->origIpSrc[0] == usrSkbfound->ipSrc[0] && usrSkbfound->origIpSrc[1] == usrSkbfound->ipSrc[1] && usrSkbfound->origIpSrc[2] == usrSkbfound->ipSrc[2] && usrSkbfound->origIpSrc[3] == usrSkbfound->ipSrc[3]) {
                                log_->error("Error processing connection:\nIP src: %1.1d.%1.1d.%1.1d.%1.1d\nIP dst: %1.1d.%1.1d.%1.1d.%1.1d\nPort src: %d\nPort dst: %d\n %s",
                                        usrSkbfound->origIpSrc[0], usrSkbfound->origIpSrc[1], usrSkbfound->origIpSrc[2], usrSkbfound->origIpSrc[3],
                                        usrSkbfound->ipDst[0], usrSkbfound->ipDst[1], usrSkbfound->ipDst[2], usrSkbfound->ipDst[3],
                                        usrSkbfound->portSrc, usrSkbfound->portDst,
                                        except.getExceptionMsg().c_str());
                            } else {
                                log_->error("Error processing connection:\nIP src: %1.1d.%1.1d.%1.1d.%1.1d\nIP dst: %1.1d.%1.1d.%1.1d.%1.1d\nPort src: %d\nPort dst: %d\n %s",
                                        usrSkbfound->origIpSrc[0], usrSkbfound->origIpSrc[1], usrSkbfound->origIpSrc[2], usrSkbfound->origIpSrc[3],
                                        usrSkbfound->ipSrc[0], usrSkbfound->ipSrc[1], usrSkbfound->ipSrc[2], usrSkbfound->ipSrc[3],
                                        usrSkbfound->portDst, usrSkbfound->portSrc,
                                        except.getExceptionMsg().c_str());
                            }
                        }
                    }
                } else {
                    log_->debug("CODE ERROR: Status not considered\n");
                }
            }

            pthread_mutex_unlock(&usrSkbfound->skbmutex);
            returnSkb(usrSkbfound);
        }

        log_->debug("Est TCP - msg END PROCESSING -----\n");
    }
}



uint8_t *PacketSniffer::createJSONMsg(uint8_t *data, event_t *eventPtr, uint32_t& offset, bool extraData) {
    char *dataPtr;
    char *dataPtrOrig;
    uint8_t nodeIP = LOCAL_NODE_IP_SRC;
    uint32_t latencyRTT;
    uint32_t latencyLocal;

    dataPtrOrig = dataPtr = (char *)data + offset;

    sprintf(dataPtr, "{\"srcIP\":\"");
    dataPtr += 10;


    const char *resIP = inet_ntop(AF_INET, (const void *)(eventPtr->ipSrc), dataPtr, INET_ADDRSTRLEN + 1);
    if (resIP == NULL) {

    }
    dataPtr = strchr((char *)data, '\0');
    sprintf(dataPtr, "\",\"dstIP\":\"");
    dataPtr += 11;
    resIP = inet_ntop(AF_INET, (const void *)(eventPtr->ipDst), dataPtr, INET_ADDRSTRLEN + 1);
    if (resIP == NULL) {

    }
    dataPtr = strchr((char *)dataPtr, '\0');

    ProcessIdentifier::ProcessData processData = {NO_PROCESS_PID, "?", "?", NO_PROCESS_PID, 0xFFFFFFFF, 0};

    if (Interface::isLocal(*((uint32_t *)eventPtr->ipSrc))) {
        log_->debug("---CONNECTION FROM LOCAL-SRC IP: %X\n", (*((uint32_t *)eventPtr->ipSrc)));
        nodeIP = LOCAL_NODE_IP_SRC;
        processData = pConnectingIdentifier_->getProcessData(eventPtr->pid);
        if (processData.pid == NO_PROCESS_PID) {
            if (strcmp(eventPtr->code,CODE_TCP_SYN_RESET_STR) != 0) {
                log_->warning("Local process data not found-SRC IP: %X\n", (*((uint32_t *)eventPtr->ipSrc)));
            } else {
                log_->debug("Local process data not found-SRC IP: %X\n", (*((uint32_t *)eventPtr->ipSrc)));
            }
        } else {
            log_->debug("Local process data found. PID: %d\n", processData.pid);
        }
        latencyRTT = eventPtr->cevt.latency1;
        latencyLocal = eventPtr->cevt.latency2;
    } else if (Interface::isLocal(*((uint32_t *)eventPtr->ipDst))) {
        log_->debug("---CONNECTION FROM OTHER TO LOCAL-DST IP: %X\n", (*((uint32_t *)eventPtr->ipDst)));
        nodeIP = LOCAL_NODE_IP_DST;
        processData = pListeningIdentifier_->identifyListenProcess((*((uint32_t *)eventPtr->ipDst)), eventPtr->portDst);
        if (processData.pid == NO_PROCESS_PID) {
            if (strcmp(eventPtr->code,CODE_TCP_SYN_RESET_STR) != 0) {
                log_->warning("Local process data not found-SRC IP: %X\n", (*((uint32_t *)eventPtr->ipDst)));
            }
        } else {
            log_->debug("Local process data found. PID: %d\n", processData.pid);
        }
        latencyRTT = eventPtr->cevt.latency2;
        latencyLocal = eventPtr->cevt.latency1;
    } else {
        log_->warning("---CANNOT IDENTIFY LOCAL FOR CONNECTION\n");
        nodeIP = LOCAL_NODE_IP_THIRD;
        latencyRTT = eventPtr->cevt.latency1;
        latencyLocal = eventPtr->cevt.latency2; //In this case it's not local but the other node to send 3-way-handshake's ACK
    }

    unsigned long timems = eventPtr->cevt.initTimeStamp.tv_sec * 1000 + eventPtr->cevt.initTimeStamp.tv_usec / 1000;
    unsigned long timemicros = eventPtr->cevt.initTimeStamp.tv_usec % 1000;

    int charsWritten =
            sprintf(dataPtr, "\",\"nodeIP\": %1.1u,\"srcPort\": %u,\"dstPort\": %u,\"code\":\"%s\","
            "\"value\": %u,\"quality\": %1.1u,\"if\":\"%s\",\"pid\":\"%d\",\"cmd\":\"%s\",\"processName\":\"%s\",\"timemillis\":\"%lu\",\"timemicros\":\"%lu\","
            "\"latency\":%u,\"extra\": {\"LatencyLocal\": %u",
            nodeIP, eventPtr->portSrc, eventPtr->portDst, eventPtr->code, eventPtr->value, eventPtr->cevt.quality, Configuration::getInstance().pcapDevice.c_str(),
            (processData.pid == NO_PROCESS_PID) ? processData.pid : -1, (processData.pid == NO_PROCESS_PID) ? processData.longCmd.c_str() : "",
                    (processData.pid == NO_PROCESS_PID) ? processData.shortName.c_str() : "", timems, timemicros,
                    latencyRTT, latencyLocal);

    //Assume charsWritten is not negative
    dataPtr += charsWritten;
    if (extraData) {
        charsWritten = sprintf(dataPtr, ",\"evtSrc\": %1.1u}}", eventPtr->cevt.evtSrc);
    } else {
        charsWritten = sprintf(dataPtr, "}}");
    }

    offset += (dataPtr + charsWritten - dataPtrOrig);
    return data;
}



void PacketSniffer::packetDumperProcessorThr(PacketSniffer *ps, FastQueue<skb_holder_t> *skbQ)
{
    PacketSniffer *packetSnifferInst = ps;
    skb_holder_t *eventHolderPtr;
    FastQueue<skb_holder_t> *skbQueue = skbQ;

    while(!packetSnifferInst->finalEmptyQ_)
    {
        //By default, if there are no events in the queue, pop gets blocked for up to 10s
        //If during those 10s it could not get an event, it returns nullptr
        eventHolderPtr = skbQueue->pop();
        if (eventHolderPtr) {
            if (!packetSnifferInst->finalEmptyQ_) {
                FrameStoreHandler *frameStoreHandler = FrameStoreHandler::getInstance();
                frameStoreHandler->dump(eventHolderPtr->skb, packetSnifferInst->pcapMgr_);
            }
            RESET_SKB_DUMP_PENDING(eventHolderPtr->skb);
            RESET_SKB_DUMPING(eventHolderPtr->skb);
            if (eventHolderPtr->retRequired) returnSkb(eventHolderPtr->skb);

            packetSnifferInst->mMgrSkbHolder_->returnInstance(eventHolderPtr);
        }
    }
    packetSnifferInst->log_->info("FINISHING packetDumperProcessorThr, emptying queue\n");

    eventHolderPtr = skbQueue->pop(10ms);
    while(eventHolderPtr)
    {
        pthread_mutex_unlock(&eventHolderPtr->skb->skbmutex);
        if (eventHolderPtr->retRequired) returnSkb(eventHolderPtr->skb);

        packetSnifferInst->mMgrSkbHolder_->returnInstance(eventHolderPtr);
        eventHolderPtr = skbQueue->pop(10ms);
    }
    packetSnifferInst->log_->info("FINISHING packetDumperProcessorThr, queue is empty\n");
}

void PacketSniffer::PCAPLoopThr(PacketSniffer *ps) {
    PacketSniffer *packetSnifferInst = ps;
    packetSnifferInst->pcapMgr_->runLoop(processPCAPPacketCallback, (u_char *)packetSnifferInst);
    packetSnifferInst->log_->info("Completed PCAP Loop\n");
}

void PacketSniffer::processIdentifierThr(PacketSniffer *ps) {
    PacketSniffer *packetSnifferInst = ps;
    event_t *eventPtr;

    while(!packetSnifferInst->finalEmptyQ_) {
        eventPtr = packetSnifferInst->idProcessQueue_->pop();
        if (eventPtr) {
            if (strcmp(eventPtr->code, CODE_TCP_SYN_BEGIN) == 0) {
                skb_t *tempSkb = (skb_t *)eventPtr->extra;
                ProcessIdentifier::ProcessData pd;
                if (eventPtr->value == 0) {
                    packetSnifferInst->pConnectingIdentifier_->identifyConnectingLocalProcess(*(uint32_t *)(eventPtr->ipSrc), eventPtr->portSrc, &(tempSkb->pid));
                    if (tempSkb->pid > -1) {
                        pd = packetSnifferInst->pConnectingIdentifier_->getProcessData(tempSkb->pid);
                    } else {
                        ApplicationLog::getLog().debug("PID NOT FOUND: %d\n", tempSkb->pid);
                        packetSnifferInst->zeroProcessData(pd);
                    }
                    //Caution: here we cast eventPtr to (flow_t *) assuming they both begin with the same 4 fields
                    //This is not nice but good for performance
                    packetSnifferInst->startFlowsManager_.addNewFlow((flow_t *)eventPtr, &eventPtr->cevt.initTimeStamp, pd.pid, pd.ppid, pd.uid, pd.shortName.c_str());

                    //Only after calling identifyConnectingLocalProcess we can RESET PID_SEARCHING because
                    //identifyConnectingLocalProcess uses the skb_t and we don't want it to be released in the middle.
                    RESET_SKB_PID_SEARCHING((skb_t *)eventPtr->extra);
                } else {
                    pd = packetSnifferInst->pListeningIdentifier_->identifyListenProcess((*((uint32_t *)eventPtr->ipDst)), eventPtr->portDst);
                    //Caution: here we cast eventPtr to (flow_t *) assuming they both begin with the same 4 fields
                    //This is not nice but good for performance
                    packetSnifferInst->startFlowsManager_.addNewFlow((flow_t *)eventPtr, &eventPtr->cevt.initTimeStamp, pd.pid, pd.ppid, pd.uid, pd.shortName.c_str());

                    //Only after calling identifyConnectingLocalProcess we can RESET PID_SEARCHING because
                    //identifyConnectingLocalProcess uses the skb_t and we don't want it to be released in the middle.
                    RESET_SKB_PID_SEARCHING((skb_t *)eventPtr->extra);
                }
            } else { //This is an END event
                //Caution: here we assume they both begin with the same 4 fields
                //This is not nice but good for performance
                end_flow_t flowEnd;
                ProcessIdentifier::ProcessData pd;
                memcpy(&flowEnd, eventPtr, (sizeof(uint16_t) + IPV4_ADDR_LEN) * 2);
                memcpy(&flowEnd.cevt, &(eventPtr->cevt), sizeof(common_evt_t));

                if (Interface::isLocal(*((uint32_t *)eventPtr->ipSrc))) {
                    if (eventPtr->pid != -1) {
                        pd = packetSnifferInst->pConnectingIdentifier_->getProcessData(eventPtr->pid);
                        if (pd.pid == NO_PROCESS_PID) {
                            ApplicationLog::getLog().warning("PID NOT FOUND in end event flow connecting: %d\n", eventPtr->pid);
                        }
                    } else { //TODO: We don't have a way of searching by addr, port in pConnectingIdentifier_
                        packetSnifferInst->zeroProcessData(pd);
                    }
                } else {
                    if (eventPtr->pid != -1) {
                        pd = packetSnifferInst->pListeningIdentifier_->getProcessData(eventPtr->pid);
                        if (pd.pid == NO_PROCESS_PID) {
                            ApplicationLog::getLog().infov("PID NOT FOUND in end event flow listening: %d\n", eventPtr->pid);
                        }
                    } else {
                        pd = packetSnifferInst->pListeningIdentifier_->getListenProcessFromIPPort(*((uint32_t *)eventPtr->ipDst), eventPtr->portDst);
                        if (pd.pid == NO_PROCESS_PID) {
                            ApplicationLog::getLog().infov("PID NOT FOUND in end event flow listening: addr %X, port %u\n", *((uint32_t *)eventPtr->ipDst), eventPtr->portDst);
                        }
                    }
                }
                flowEnd.process.pid = pd.pid;
                flowEnd.process.ppid = pd.ppid;
                flowEnd.process.uid = pd.uid;
                strcpy(flowEnd.process.shortName, pd.shortName.c_str());

                packetSnifferInst->endFlowsManager_.addNewFlow(&flowEnd);
            }
            packetSnifferInst->mMgrEvent_->returnInstance(eventPtr);
        }
    }

    packetSnifferInst->log_->info("FINISHING processIdentifierThr, emptying queue\n");

    eventPtr = packetSnifferInst->idProcessQueue_->pop(10ms);

    while(eventPtr) {
        packetSnifferInst->mMgrEvent_->returnInstance(eventPtr);
        eventPtr = packetSnifferInst->idProcessQueue_->pop(10ms);
    }

    packetSnifferInst->log_->info("FINISHING processIdentifierThr, queue is empty\n");
}

int PacketSniffer::processFlowBegin(skb_t *usrSkb) {
    event_t *eventPtr = getNewEvent();
    if (eventPtr) {
        populateEvent(eventPtr, usrSkb, usrSkb->initialTime, CODE_TCP_SYN_BEGIN, 0, 0);
        SET_SKB_PID_SEARCHING(usrSkb);
        eventPtr->extra = (skb_t *)usrSkb;
        bool res = fastQueueEvt_->push(eventPtr);
        if (!res) {
            log_->error("Error enqueuing event. Discarding event.\n");
            mMgrEvent_->returnInstance(eventPtr);
            return -3;
        }
    } else {
        return -1;
    }

    return 0;
}

int PacketSniffer::processFlowEnd(skb_t *usrSkb, struct timeval& timestamp, ConnectionEndType_t endType, uint8_t direc) {
    event_t *eventPtr = getNewEvent();
    if (eventPtr) {
        populateEvent(eventPtr, usrSkb, usrSkb->initialTime, CODE_TCP_END, 0, 0);
        eventPtr->cevt.latency3 = usrSkb->latency3;
        if (usrSkb->isTLS == 1) {
            eventPtr->cevt.connType = CONN_TLS;
        } else if (usrSkb->isHTTPDecision == 1) {
            eventPtr->cevt.connType = CONN_PLAIN_HTTP;
        } else if (usrSkb->isHTTPDecision == 2) {
            eventPtr->cevt.connType = CONN_PLAIN_UNKNOWN;
        } else {
            eventPtr->cevt.connType = CONN_UNKNOWN;
        }
        eventPtr->cevt.endType = endType;
        eventPtr->cevt.evtSrc = direc;
        eventPtr->cevt.endTimeStamp = timestamp;

        eventPtr->cevt.dataTo = usrSkb->dataTo;
        eventPtr->cevt.dataFrom = usrSkb->dataFrom;
        eventPtr->pid = usrSkb->pid;

        bool res = fastQueueEvt_->push(eventPtr);
        if (!res) {
            log_->error("Error enqueuing event. Discarding event.\n");
            mMgrEvent_->returnInstance(eventPtr);
            return -3;
        }
    } else {
        return -1;
    }

    return 0;
}


void PacketSniffer::evtProcessorThr(PacketSniffer *ps, FastQueue<event_t> *eventQ)
{
    uint8_t data[MAX_EVENT_MSG_LEN + 1];
    PacketSniffer *packetSnifferInst = ps;
    event_t *eventPtr;
    FastQueue<event_t> *eventQueue = eventQ;

    while(!packetSnifferInst->finalEmptyQ_)
    {
        //By default, if there are no events in the queue, pop gets blocked for up to 10s
        //If during those 10s it could not get an event, it returns nullptr
        eventPtr = eventQueue->pop();

        if (eventPtr) {
            bool keepPopping = true;
            uint32_t offset = 0;
            packetSnifferInst->connector_->formatJSONBegin(data, offset);
            int reportedEventsCount = 0;
            while(keepPopping && eventPtr) {
                if (!packetSnifferInst->finalEmptyQ_) {
                    if (strcmp(eventPtr->code, CODE_TCP_SYN_BEGIN) != 0) {
                        if (strcmp(eventPtr->code, CODE_TCP_END) != 0) {
                            bool extraData;

                            reportedEventsCount++;

                            if (strcmp(eventPtr->code, CODE_TCP_RESET_STR) == 0 || strcmp(eventPtr->code, CODE_TLS_ALERT_STR) == 0 ) extraData = true;
                            else extraData = false;

                            packetSnifferInst->createJSONMsg(data, eventPtr, offset, extraData);
                            packetSnifferInst->connector_->formatJSONNext(data, offset);
                            packetSnifferInst->mMgrEvent_->returnInstance(eventPtr);
                        } else {
                            bool res = packetSnifferInst->idProcessQueue_->push(eventPtr);
                            if (!res) {
                                packetSnifferInst->log_->debug("Could not enqueue END EVENT in IPQUEUE for process identification: %X - %u\n", *((uint32_t *)eventPtr->ipSrc),eventPtr->portSrc);
                                packetSnifferInst->mMgrEvent_->returnInstance(eventPtr);
                            }
                        }
                    } else {
                        if (Interface::isLocal(*((uint32_t *)eventPtr->ipSrc))) {
                            eventPtr->value = 0;
                            bool res = packetSnifferInst->idProcessQueue_->push(eventPtr);
                            if (!res) {
                                RESET_SKB_PID_SEARCHING((skb_t *)eventPtr->extra);
                                packetSnifferInst->log_->debug("Could not enqueue SYN event in IPQUEUE for process identification: %X - %u\n", *((uint32_t *)eventPtr->ipSrc),eventPtr->portSrc);
                                packetSnifferInst->mMgrEvent_->returnInstance(eventPtr);
                            }
                        } else if (Interface::isLocal(*((uint32_t *)eventPtr->ipDst))) {
                            eventPtr->value = 1;
                            bool res = packetSnifferInst->idProcessQueue_->push(eventPtr);
                            if (!res) {
                                RESET_SKB_PID_SEARCHING((skb_t *)eventPtr->extra);
                                packetSnifferInst->log_->debug("Could not enqueue event in IPQUEUE for process identification: %X - %u\n", *((uint32_t *)eventPtr->ipDst),eventPtr->portDst);
                                packetSnifferInst->mMgrEvent_->returnInstance(eventPtr);
                            }
                        } else {
                            RESET_SKB_PID_SEARCHING((skb_t *)eventPtr->extra);
                            packetSnifferInst->mMgrEvent_->returnInstance(eventPtr);
                        }
                    }
                    if ((MAX_EVENT_MSG_LEN - offset) < 400) {
                        keepPopping = false;
                    } else {
                        eventPtr = eventQueue->pop(3000ms);
                    }
                } else {
                    packetSnifferInst->mMgrEvent_->returnInstance(eventPtr);
                    keepPopping = false;
                }
            }
            if (!packetSnifferInst->finalEmptyQ_) {
                if (reportedEventsCount > 0) {
                    packetSnifferInst->connector_->formatJSONEnd(data, offset);
                    packetSnifferInst->connector_->sendData(Configuration::getInstance().eventResource, (const char *)data, offset);
                }
            }
        }
    }
    packetSnifferInst->log_->info("FINISHING evtProcessorThr, emptying queue\n");

    eventPtr = eventQueue->pop(10ms);

    while(eventPtr) {
        packetSnifferInst->mMgrEvent_->returnInstance(eventPtr);
        eventPtr = eventQueue->pop(10ms);
    }

    packetSnifferInst->log_->info("FINISHING evtProcessorThr, queue is empty\n");
}



int PacketSniffer::enqueueSkb(skb_t *usrSkb, bool retRequired) {
    try {
        skb_holder_t *skbPtr = mMgrSkbHolder_->createInstance();
        if (skbPtr) {
            skbPtr->skb = usrSkb;
            skbPtr->retRequired = retRequired;
            SET_SKB_DUMPING(usrSkb);
            bool res = fastQueueSkb_->push(skbPtr);
            if (!res) {
                log_->error("Error enqueuing skb holder. Skb will not be enqueued.\n");
                mMgrSkbHolder_->returnInstance(skbPtr);
                RESET_SKB_DUMPING(usrSkb);
                return -3;
            }
        } else {
            log_->error("Error: skb_holder not created.\n");
            return -1;
        }
    } catch(objmem_manager::MemoryManager<skb_holder_t, SKB_HOLDER_STR>::MemoryMgrException& excep) {
        log_->warning("Exception creating skb holder to enqueue. %s.\n", excep.getExceptionMsg().c_str());
        log_->warning("Skb will not be enqueued.\n");
        return -2;
    }

    return 0;
}



int PacketSniffer::enqueueEvent(skb_t *usrSkb, struct timeval& timeStamp, const char *code, uint32_t value, uint8_t quality, uint8_t direc) {
    event_t *eventPtr = getNewEvent();
    if (eventPtr) {
        populateEvent(eventPtr, usrSkb, timeStamp, code, value, quality);
        eventPtr->cevt.evtSrc = direc;
        bool res = fastQueueEvt_->push(eventPtr);
        if (!res) {
            log_->error("Error enqueuing event. Discarding event.\n");
            mMgrEvent_->returnInstance(eventPtr);
            return -3;
        }
    } else {
        return -1;
    }
    return 0;
}

int PacketSniffer::enqueueEvent(event_t *eventPtr) {
    bool res = fastQueueEvt_->push(eventPtr);
    if (!res) {
        log_->error("Error enqueuing event. Discarding event.\n");
        mMgrEvent_->returnInstance(eventPtr);
        return -3;
    }
    return 0;
}


int PacketSniffer::processTCPEstablishedMessage(skb_t *usrSkb, struct timeval& timeStamp, uint8_t *ipSrc, uint16_t portSrc, uint32_t tcpDataLen) {
    uint32_t ipAddr = *((uint32_t *)ipSrc);

#ifdef GDB_SRV
//    log_->debug("PROCESSING DATA TCP MSG LEN: %d\n", tcpMsgLen);
#endif

    // Only ask for KILLED - The socket could be NOT valid at this moment
    if (!IS_SKB_STATE_KILLED(usrSkb)) {

        if (usrSkb->isTLS > 0 && usrSkb->isTLS < 3) {
            //If IS_SKB_DUMP_PENDING there was an alert or error and it doesn't make sense to keep processing TLS messages
            if (!IS_SKB_DUMP_PENDING(usrSkb)) {
                try {
                    if (!IS_DO_NOT_PARSE(usrSkb)) {
                        usrSkb->tlsInterpreter->tempTimestamp = timeStamp;
                        usrSkb->tlsInterpreter->process();
                        if (usrSkb->tlsInterpreter->handshakeDone) {
                            if (portSrc == usrSkb->portSrc && *((uint32_t *)usrSkb->ipSrc) == ipAddr) {
                                updateDataTo(usrSkb, tcpDataLen);
                            } else {
                                updateDataFrom(usrSkb, tcpDataLen);
                            }
                            if (usrSkb->dataFrom > 1000 || usrSkb->dataTo > 1000) {
                                SET_DO_NOT_PARSE(usrSkb);
                            }
                        }
                    }
                } catch(TLSException& e) {
                    uint8_t codeEx = e.getCode();
                    uint8_t code = usrSkb->tlsInterpreter->getAlertCode();
                    uint8_t severity = 0;
                    uint8_t quality = 1;
                    bool processAlert = true;

                    if (!Configuration::getInstance().incomingInternetConnections) {
                        if (Interface::isFromInternet(*((uint32_t *)usrSkb->ipSrc), *((uint32_t *)usrSkb->ipDst))) {
                            if (countSSLFromInternet_ < kMaxCountSSLFromInternet_) {
                                countSSLFromInternet_++;
                                quality = 0;
                            } else {
                                processAlert = false;
                            }
                        }
                    }

                    if (processAlert && codeEx == TLSInterpreter::kAlertException) {
                        uint8_t direc;

                        if (portSrc == usrSkb->portSrc && *((uint32_t *)usrSkb->ipSrc) == ipAddr) {
                            direc  = FROM_INITIATOR;
                        } else {
                            direc  = FROM_DST;
                        }
                        severity = usrSkb->tlsInterpreter->getAlertSeverity();
                        if (code == 0) { //Close_notify
                            //TODO:Need to review this because we don't want a server to send millions of events!!!!
                            //TODO: THIS IS A BUG!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
                            if (!Configuration::getInstance().NoHTTPSClientSSLShutdownEvent) {
                                enqueueEvent(usrSkb, timeStamp, CODE_TLS_ALERT_STR, ((uint16_t)severity<<8 | (uint16_t)code), quality, direc);
                                SET_SKB_DUMP_PENDING(usrSkb);
                                processFlowEnd(usrSkb, timeStamp, CONN_END_TLS_ALERT, direc);
                            } else if (!IS_HTTPS(usrSkb->portDst) || !(Interface::isLocal(*((uint32_t *)usrSkb->ipSrc)))) {
                                enqueueEvent(usrSkb, timeStamp, CODE_TLS_ALERT_STR, ((uint16_t)severity<<8 | (uint16_t)code), quality, direc);
                                SET_SKB_DUMP_PENDING(usrSkb);
                                processFlowEnd(usrSkb, timeStamp, CONN_END_TLS_ALERT, direc);
                            } // For close_notify we decided not to send event if HTTPS and client is local
                        } else {
                            enqueueEvent(usrSkb, timeStamp, CODE_TLS_ALERT_STR, ((uint16_t)severity<<8 | (uint16_t)code), quality, direc);
                            SET_SKB_DUMP_PENDING(usrSkb);
                        }
                    } else if (processAlert) {
                        SET_DO_NOT_PARSE(usrSkb);
                        if (!usrSkb->tlsInterpreter->handshakeDone) {
                            enqueueEvent(usrSkb, timeStamp, CODE_TLS_EXCEP_STR, code, 1);
                            SET_SKB_DUMP_PENDING(usrSkb);
                        } else {
                            if (usrSkb->dataFrom <= 1000 || usrSkb->dataTo <= 1000) {
                                enqueueEvent(usrSkb, timeStamp, CODE_TLS_EXCEP_STR, code, 1);
                                SET_SKB_DUMP_PENDING(usrSkb);
                            }
                        }
                    }
                }
            }
        } else {
            //If IS_SKB_DUMP_PENDING there was an alert or error and it doesn't make sense to keep processing TLS messages
            if (!IS_SKB_DUMP_PENDING(usrSkb)) {
                if (portSrc == usrSkb->portSrc && *((uint32_t *)usrSkb->ipSrc) == ipAddr) {
                    updateDataTo(usrSkb, tcpDataLen);
                } else {
                    updateDataFrom(usrSkb, tcpDataLen);
                }
                if (!IS_DO_NOT_PARSE(usrSkb)) {
                    //This is not an SSL connection. Is it HTTP plain text?
                    if (isHTTP(usrSkb)) {
                        usrSkb->httpInterpreter->process();
                    } else {
                        if (usrSkb->isHTTPDecision == 0) {
                            //Donothing
                        } else {
                            //Donothing
                        }
                    }
                }
            }
        }
    }

    return 0;
}




void PacketSniffer::processConnectingSkbList() {
    uint16_t cnt = 0;
    uint8_t end = 0;
    skb_t *currentSkb;
    skb_t *nextSkb;
    time_t timeval1;
    time_t timeval2;
    uint32_t killedcnt = 0;
    uint32_t totalcnt = 0;

    timeval1 = time(NULL);

    log_->info("ABOUT TO PROCESS CONNECTING SKB LIST - TIME: %ju\n", (uintmax_t)timeval1);

    if (listConnectingSkb) {
        //pthread_mutex_lock(&createMutex);

        currentSkb = listConnectingSkb;

        //pthread_mutex_unlock(&createMutex);

        while(!end) {
            if (cnt >= MAX_SKB_PROCESS_SET) {
                sched_yield();
                cnt = 0;
            }

            pthread_mutex_lock(&currentSkb->skbmutex);

            if (currentSkb->next) {
                nextSkb = currentSkb->next;
            }
            else {
                nextSkb = NULL;
                end = 1;
            }

            if (!IS_SKB_STATE_KILLED(currentSkb)) {
                if (currentSkb->cStatus == ESTABLISHED || currentSkb->cStatus == LAST_HSHAKE_ACK) {
                    RESET_KEEPALIVE_CNT_MASK(currentSkb);
                    moveSkbToEstablishedQ(currentSkb);
                } else {
                    INC_KEEPALIVE_CNT_MASK(currentSkb);
                    if (IS_KEEPALIVE_CNT_THR(currentSkb, KEEPALIVE_CNT_THR_PARTIAL_CONNETION)) {
                        processConnectingKilledNotification(currentSkb);
                        SET_SKB_STATE_KILLED(currentSkb);
                    }
                }
            } else {
                if (IS_SKB_DUMP_PENDING(currentSkb)) {
                    if (!IS_SKB_DUMPING(currentSkb)) {
                        enqueueSkb(currentSkb);
                        RESET_MARKED_FOR_DUMP(currentSkb); //In case it was set
                        removeMarkedForDump(currentSkb);
                        RESET_SKB_DUMP_PENDING(currentSkb);
                    }
                } else if (IS_MARKED_FOR_DUMP(currentSkb)) {
                    if (!IS_SKB_DUMPING(currentSkb)) {
                        enqueueSkb(currentSkb);
                        RESET_MARKED_FOR_DUMP(currentSkb);
                        removeMarkedForDump(currentSkb);
                    }
                } else if (!IS_SKB_DUMPING(currentSkb)) {
                    if (!IS_SKB_PID_SEARCHING(currentSkb)) {
                        removeMarkedForDump(currentSkb);
                        if (Interface::isLocal(*((uint32_t *)currentSkb->ipSrc))) {
                            pConnectingIdentifier_->deletePending(*((uint32_t *)currentSkb->ipSrc), currentSkb->portSrc);
                        } else {
                            pListeningIdentifier_->deletePending(*((uint32_t *)currentSkb->ipDst), currentSkb->portDst);
                        }
                        disposeSkbResources(currentSkb);
                        //nextSkb is pointing to the next skb in this list
                        if (submitDeleteConnectingSkb(currentSkb) == 1) {
                            //Caution: Do not do anything else with *currentSkb as now it might be used
                            //by another thread
                            killedcnt++;
                        }
                    }
                }
            }

            pthread_mutex_unlock(&currentSkb->skbmutex);

            currentSkb = nextSkb;

            cnt++;
            totalcnt++;
        }
        timeval2 = time(NULL);

        log_->info("FINISHED PROCESSING CONNECTING SKB LIST - TIME: %ju\n", (uintmax_t)timeval2);
        log_->info("TOTAL: %u - KILLED: %u\n", totalcnt, killedcnt);
    }
}


void PacketSniffer::processEstablishedSkbList() {
    uint16_t cnt = 0;
    uint8_t end = 0;
    skb_t *currentSkb;
    skb_t *nextSkb;
    time_t timeval1;
    time_t timeval2;
    uint32_t killedcnt = 0;
    uint32_t totalcnt = 0;

    timeval1 = time(NULL);

    log_->info("ABOUT TO PROCESS ESTABLISHED SKB LIST - TIME: %ju\n", (uintmax_t)timeval1);

    if (listEstablishedSkb) {
        //pthread_mutex_lock(&createMutex);

        currentSkb = listEstablishedSkb;

        //pthread_mutex_unlock(&createMutex);

        while(!end) {
            if (cnt >= MAX_SKB_PROCESS_SET) {
                sched_yield();
                cnt = 0;
            }

            pthread_mutex_lock(&currentSkb->skbmutex);

            if (currentSkb->next) {
                nextSkb = currentSkb->next;
            }
            else {
                nextSkb = NULL;
                end = 1;
            }

            if (!IS_SKB_STATE_KILLED(currentSkb)) {
                INC_KEEPALIVE_CNT_MASK(currentSkb);
                if (IS_KEEPALIVE_CNT_THR(currentSkb, Configuration::getInstance().keepaliveThresholdStaleEstablished)) {
                    if (!IS_SKB_NOTIFICATION_SENT(currentSkb)) {
                        processStaleNotification(currentSkb);
                        SET_SKB_NOTIFICATION_SENT(currentSkb);
                    }
                    if (IS_KEEPALIVE_CNT_THR(currentSkb, Configuration::getInstance().keepaliveThresholdEstablishedKilled)) {
                        int ret = processEstablishedKilledNotification(currentSkb);
                        if (ret == 0 && !IS_SKB_DUMPING(currentSkb)) {
                            enqueueSkb(currentSkb);
                        }
                        SET_SKB_STATE_KILLED(currentSkb);
                    }
                }
            } else {
                if (IS_SKB_DUMP_PENDING(currentSkb)) {
                    if (!IS_SKB_DUMPING(currentSkb)) {
                        enqueueSkb(currentSkb);
                        RESET_MARKED_FOR_DUMP(currentSkb); //In case it was set
                        removeMarkedForDump(currentSkb);
                        RESET_SKB_DUMP_PENDING(currentSkb);
                    }
                } else if (IS_MARKED_FOR_DUMP(currentSkb)) {
                    if (!IS_SKB_DUMPING(currentSkb)) {
                        enqueueSkb(currentSkb);
                        RESET_MARKED_FOR_DUMP(currentSkb);
                        removeMarkedForDump(currentSkb);
                    }
                } else if (!IS_SKB_DUMPING(currentSkb)){
                    if (!IS_SKB_PID_SEARCHING(currentSkb)) {
                        removeMarkedForDump(currentSkb);
                        if (Interface::isLocal(*((uint32_t *)currentSkb->ipSrc))) {
                            pConnectingIdentifier_->deletePending(*((uint32_t *)currentSkb->ipSrc), currentSkb->portSrc);
                        } else {
                            pListeningIdentifier_->deletePending(*((uint32_t *)currentSkb->ipDst), currentSkb->portDst);
                        }
                        disposeSkbResources(currentSkb);
                        //nextSkb is pointing to the next skb in this list
                        if (submitDeleteEstablishedSkb(currentSkb) == 1) {
                            //Caution: Do not do anything else with *currentSkb as now it might be used
                            //by another thread
                            killedcnt++;
                        }
                    }
                }
            }

            pthread_mutex_unlock(&currentSkb->skbmutex);

            currentSkb = nextSkb;

            cnt++;
            totalcnt++;
        }
        timeval2 = time(NULL);

        log_->info("FINISHED PROCESSING ESTABLISHED SKB LIST - TIME: %ju\n", (uintmax_t)timeval2);
        log_->info("TOTAL: %u - KILLED: %u\n", totalcnt, killedcnt);
    }
}

void PacketSniffer::cleanConnectingSkbList() {
    skb_t *currentSkb;
    skb_t *nextSkb;

    currentSkb = listConnectingSkb;

    while(currentSkb) {
        nextSkb = currentSkb->next;
        disposeSkbResources(currentSkb);
        submitDeleteConnectingSkb(currentSkb);
        currentSkb = nextSkb;
    }
}

void PacketSniffer::cleanEstablishedSkbList() {
    skb_t *currentSkb;
    skb_t *nextSkb;

    currentSkb = listEstablishedSkb;

    while(currentSkb) {
        nextSkb = currentSkb->next;
        disposeSkbResources(currentSkb);
        submitDeleteEstablishedSkb(currentSkb);
        currentSkb = nextSkb;
    }
}

void PacketSniffer::disposeSkbResources(skb_t *currentSkb) {
    FrameStoreHandler::getInstance()->deleteFrameBufferList(currentSkb);
    if (currentSkb->tlsInterpreter != nullptr) {
        delete currentSkb->tlsInterpreter;
        currentSkb->tlsInterpreter = nullptr;
    }
}

void PacketSniffer::processSkbListThread(PacketSniffer *ps)
{
    PacketSniffer *packetSnifferInst = ps;
    struct timeval timeinterval;
    int res;
    int periodCounter = 0;

    while(!packetSnifferInst->end)
    {
        timeinterval.tv_sec = SKB_LIST_PROCESS_PERIOD_SEC;
        timeinterval.tv_usec = 0;
        periodCounter++;

        res = select(0, NULL, NULL, NULL, &timeinterval);

        if (res < 0)
        {
            packetSnifferInst->log_->error("Error in select: %d\n", errno);
        }

        packetSnifferInst->processConnectingSkbList();
        if (periodCounter == SKB_LIST_PROCESS_ESTABLISHED_PERIODS) {
            packetSnifferInst->processEstablishedSkbList();
            //Process dumps required
            skb_t *processedSkb = processDumpRequired(300);
            while(processedSkb != nullptr) {
                processedSkb = processDumpRequired(300);
                pthread_mutex_lock(&processedSkb->skbmutex);
                packetSnifferInst->enqueueSkb(processedSkb);
                pthread_mutex_unlock(&processedSkb->skbmutex);
            }
            periodCounter = 0;
        }
        //logSkbManagementData();
    }
    packetSnifferInst->log_->info("FINISHING processSkbListThread\n");

    while(packetSnifferInst->msgProcessorIsRunning_) {
        std::this_thread::sleep_for(1s);
    }

    cleanMarkedForDump();
    packetSnifferInst->cleanConnectingSkbList();
    packetSnifferInst->cleanEstablishedSkbList();

    packetSnifferInst->log_->info("FINISHING processSkbListThread - Cleaned queues\n");

}

/******************************************
 * Management Command Execution
 ******************************************/

std::function<void (const struct timeval&)> PacketSniffer::getTimedAction() {
    return [&](const struct timeval& timeNow) -> void {
        if (timeNow.tv_sec - lastTimeCounterReset_.tv_sec > (3600 * hoursToResetCounter_)) {
            lastTimeCounterReset_.tv_sec = timeNow.tv_sec;
            countResetFromInternet_ = 0;
            countConnKilledFromInternet_ = 0;
            countRepSyncFromInternet_ = 0;
            countSSLFromInternet_ = 0;
            countStaleFromInternet_ = 0;
        }
    };
}

/****************************************************
 *
 * @param ipCString ip address about which we are being asked
 * @return
 */

bool PacketSniffer::haveYouSeenThisIPLAstMinute(const char *ipCString) {
    return startFlowsManager_.haveYouSeenThisIPLAstMinute(ipCString);
}


std::list<std::function<void (const struct timeval&)>> PacketSniffer::getTimedActionsList() {
    std::list<std::function<void (const struct timeval&)>> timedActionsList;
    timedActionsList.push_back(startFlowsManager_.getTimedAction());
    timedActionsList.push_back(endFlowsManager_.getTimedAction());
    if (flowProcessManager_ != nullptr) {
        timedActionsList.push_back(flowProcessManager_->getTimedAction());
    }
    timedActionsList.push_back(getTimedAction());
    return timedActionsList;
}



