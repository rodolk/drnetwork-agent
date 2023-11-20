/*
 * connectionUnitTest.cpp
 *
 *  Created on: Jul 7, 2021
 *      Author: rodolk
 */

#include <iostream>
#include <string>

#include <pcap.h>
#include <string.h>
#include <arpa/inet.h>
#include <string.h>

#include <gtest/gtest.h>

#include "skb.h"
#include "frameBuffer.h"
#include "frameStoreHandler.h"
#include "TLSInterpreter.h"
#include "packetSniffer.h"
#include "interface.h"
#include "Connector.h"
#include "PCAPManager.h"
#include "PCAPDumper.h"
#include "Configuration.h"
#include "processIdentifierLSOF.h"

#include "common.h"
#include "TestPCAPManager.h"

#ifdef NUM_FRAME_BUFFER
#undef NUM_FRAME_BUFFER
#endif

#define NUM_FRAME_BUFFER 500
//#define NUM_FRAME_BUFFER 10000


#define LOG_DIR "./logs"
#define DEFAULT_CONFIG_FILE "./dllt.cfg"



extern DaemonLog *daemonLogging;

uint32_t gDumpedPackets = 0;

namespace connectionUnitTest {

uint8_t gAlertCode = 0;
uint8_t gAlertSeverity = 0;
uint8_t gExceptionCode = 0;

uint8_t gReceivedEventStale = 0;
uint8_t gReceivedEventConnRST = 0;
uint32_t gEventsCount = 0;
uint8_t gReceivedEventTLSAlert = 0;
uint8_t gReceivedEventTLSConn = 0;

using namespace std;



class TestConnector : public connectors::Connector {
    void sendData(std::string resource, const char *msg, uint32_t len) {
        const char *code = "00007";
        gEventsCount++;
        cout << "sendData called: " << msg << endl;
        const char *found = strstr(msg, code);
        if (found) {
            gReceivedEventStale++;
        }
    }
    virtual void formatJSONBegin(uint8_t *data, uint32_t& offset) {}
    virtual void formatJSONNext(uint8_t *data, uint32_t& offset) {}
    virtual void formatJSONEnd(uint8_t *data, uint32_t& offset) {}
};

class TestConnectorRefusedConn : public connectors::Connector {
    void sendData(std::string resource, const char *msg, uint32_t len) {
        const char *code = "00009";
        gEventsCount++;
        cout << "sendData called: " << msg << endl;
        const char *found = strstr(msg, code);
        if (found) {
            gReceivedEventConnRST++;
        }
    }
    virtual void formatJSONBegin(uint8_t *data, uint32_t& offset) {}
    virtual void formatJSONNext(uint8_t *data, uint32_t& offset) {}
    virtual void formatJSONEnd(uint8_t *data, uint32_t& offset) {}
};

class TestConnectorCloseNotify : public connectors::Connector {
    void sendData(std::string resource, const char *msg, uint32_t len) {
        const char *code = "00004";
        gEventsCount++;
        cout << "sendData called: " << msg << endl;
        const char *found = strstr(msg, code);
        if (found) {
            gReceivedEventTLSAlert++;
        }

        code = "00003";
        found = strstr(msg, code);
        if (found) {
            gReceivedEventTLSConn++;
        }

        code = "00007";
        found = strstr(msg, code);
        if (found) {
            gReceivedEventStale++;
        }
    }
    virtual void formatJSONBegin(uint8_t *data, uint32_t& offset) {}
    virtual void formatJSONNext(uint8_t *data, uint32_t& offset) {}
    virtual void formatJSONEnd(uint8_t *data, uint32_t& offset) {}
};




class Test_3MB_PCAPManager : public TestPCAPManager {
public:
    uint32_t packetCount_{0};

    Test_3MB_PCAPManager() {}
    virtual int runLoop(pcap_handler callback, u_char *args) {
        //use -1 instead of 0 as second argument. This is necessary for old pcap libraries.
        int res;
        while(!end) {
            res = pcap_loop(pcapFileHandle_, 200, callback, args);
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
                std::this_thread::sleep_for(1s);
                packetCount_++;
                if (packetCount_ >= 15) {
                    cout << "pcap_loop finished with non-negative value: " << res << ". Continue looping\n" << endl;
                    cout << " Packet Count: " << (unsigned int)packetCount_ << endl;
                    end = true;
                }
            }
        }
        return res;
    }
};

int processTCPEstablishedMessage(skb_t *usrSkb, struct timeval& timeStamp) {
    int retValue = 0;

#ifdef GDB_SRV
//    log_->debug("PROCESSING DATA TCP MSG LEN: %d\n", tcpMsgLen);
#endif

    // Only ask for KILLED - The socket could be NOT valid at this moment
    if (!IS_SKB_STATE_KILLED(usrSkb)) {
        if (usrSkb->isTLS > 0 && usrSkb->isTLS < 3) {
            try {
                usrSkb->tlsInterpreter->process();
            } catch(TLSException& e) {
                gExceptionCode = e.getCode();
                gAlertCode = usrSkb->tlsInterpreter->getAlertCode();
                if (gExceptionCode == 1) {
                    gAlertSeverity = usrSkb->tlsInterpreter->getAlertSeverity();
                }
                retValue = 1;
            }
        }
    }

    return retValue;
}




int handlePacket(msg_buffer_t *msgBuf, uint16_t step) {
    uint8_t hwHdrLen = ETHER_DEFAULT_HDR_LEN;
    uint8_t ipHdrLenW;
    //uint16_t datagramLen;
    uint16_t tcpIdx;
    //uint16_t tcpMsgLen;
    uint16_t tcpHdrLen;
    skb_t auxSkb;
    int retValue = 0;
    FrameStoreHandler *frameStoreHandler = FrameStoreHandler::getInstance();

    //cout << "-------storing packet: " << counter++ << endl;

    ipHdrLenW = msgBuf->msg[14] & 0x0F;

    tcpIdx = hwHdrLen + (ipHdrLenW * 4);
    //datagramLen = ntohs(*((uint16_t *)&msgBuf->msg[16]));
    //tcpMsgLen = datagramLen - (ipHdrLenW * 4);

    tcpHdrLen = ((msgBuf->msg[tcpIdx + 12] & 0xF0) >> 4) * 4;

    auxSkb.portSrc = ntohs(*((uint16_t *)&msgBuf->msg[tcpIdx]));
    auxSkb.portDst = ntohs(*((uint16_t *)&msgBuf->msg[tcpIdx + 2]));
    memcpy(auxSkb.ipSrc, &msgBuf->msg[26], 4);
    memcpy(auxSkb.ipDst, &msgBuf->msg[30], 4);

    if (step == 0) {
        skb_t *newSkb;

        newSkb = get_new_skb();

        memcpy((void *)newSkb, (void *)&auxSkb, SIZE_OF_IP_PORT);

        newSkb->cStatus = SYN;
        //RESET_SKB_VALID_CNT(newSkb);
        //RESET_SKB_STATE_VALID(newSkb);
        RESET_STATE(newSkb);
        newSkb->syncRetries = 0;
        newSkb->initialTime = msgBuf->hdr.ts;
        newSkb->origPortSrc = newSkb->portSrc;
        newSkb->origPortDst = newSkb->portDst;
        memcpy(newSkb->origIpSrc, newSkb->ipSrc, IPV4_ADDR_LEN);

        addNewSkb(newSkb);
        frameStoreHandler->initializeFrameBuffer(newSkb, SKB_MAX_COUNT_FB);
        frameStoreHandler->storeFrame(msgBuf->msg, msgBuf->len, &(msgBuf->hdr), newSkb);
    } else {
        skb_t *usrSkbfound;
        struct timeval timeStamp = msgBuf->hdr.ts;
        usrSkbfound = skbLookup(&auxSkb);

        frameStoreHandler->storeFrame(msgBuf->msg, msgBuf->len, &(msgBuf->hdr), usrSkbfound);

        if (step == 3) {
            usrSkbfound->cStatus = ESTABLISHED;
            TLSInterpreter *tlsInter = new TLSInterpreter(usrSkbfound, tcpIdx + tcpHdrLen);
            tlsInter->checkTLS();
            if (usrSkbfound->isTLS == 1) {
            }
        }
        retValue = processTCPEstablishedMessage(usrSkbfound, timeStamp);
    }
    return retValue;
}


void processPackets(const char *filename) {
    pcap_t *pcap;
    const unsigned char *packet;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    uint32_t msgLen;
    msg_buffer_t msgBuf;

    initializeSkb();
    FrameBuffer::initialize(NUM_FRAME_BUFFER);


    pcap = pcap_open_offline(filename, errbuf);
    if (pcap == NULL) {
        cerr << "error reading pcap file: " << errbuf << endl;
        exit(1);
    }

    int packetNum = 0;
    int retValue = 0;
    while (retValue == 0 && (packet = pcap_next(pcap, &header)) != NULL) {
        msgLen = (header.caplen > MAX_MSG_LEN) ? MAX_MSG_LEN : header.caplen;
        memcpy(msgBuf.msg, packet, msgLen);
        memcpy(&msgBuf.hdr, &header, sizeof(struct pcap_pkthdr));
        msgBuf.status = 1;
        msgBuf.len = msgLen;

        retValue = handlePacket(&msgBuf, packetNum);
        packetNum++;
    }
}

void executeStaleConnectionTests(uint16_t& testCounter) {
    std::thread *threadSnifferAgent;
    const char *filename = "./testfiles/test_connection_stale1.pcap";
    string pcapFilter = "tcp";
    string pcapDevice = filename;
    string configFileString = DEFAULT_CONFIG_FILE;

    testCounter++;
    cout << "....... TEST " << testCounter << endl;
    cout << "Test Connection Stale" << endl;

    Configuration::initialize();
    Configuration::getInstance().setConfiguredValues(configFileString);

    Configuration::getInstance().keepaliveThresholdStaleEstablished = 1;
    Configuration::getInstance().events_for_tls_connections = true;
    Configuration::getInstance().logsDirectory = LOG_DIR;

    std::list<uint32_t> ipBackSvcList;
    TestPCAPManager *pcapMgr = new TestPCAPManager();
    PacketSniffer *packetSniffer = new PacketSniffer();
    TestConnector *testConnector = new TestConnector();
    ProcessIdentifier *pIdentifierConn = new ProcessIdentifierLSOF();
    ProcessIdentifier *pIdentifierListen = new ProcessIdentifierLSOF();

    packetSniffer->initialize(*testConnector, *pcapMgr, *daemonLogging, pcapFilter, pcapDevice, ipBackSvcList, pIdentifierConn, pIdentifierListen, nullptr);

    threadSnifferAgent = new std::thread(PacketSniffer::runAgentThread, packetSniffer);

    cout << "ABOUT to enter loop" << endl;

    bool endLoop = false;
    while(!endLoop) {
        if (gReceivedEventStale > 0) break;
        std::this_thread::sleep_for(10s);
    }

    ASSERT_EQ(gEventsCount, (uint32_t)2);
    ASSERT_EQ(gReceivedEventStale, (uint8_t)1);
    ASSERT_EQ(gDumpedPackets, (uint32_t)0);

    cout << "ABOUT to finish" << endl;

    packetSniffer->endSniffing();

    threadSnifferAgent->join();

    delete pcapMgr;
    delete testConnector;
    delete packetSniffer;
    delete threadSnifferAgent;
}

void executeRefusedConnectionTests(uint16_t& testCounter) {
    std::thread *threadSnifferAgent;
    const char *filename = "./testfiles/test_connection_refused.pcap";
    string pcapFilter = "tcp";
    string pcapDevice = filename;
    string configFileString = DEFAULT_CONFIG_FILE;

    testCounter++;
    cout << "....... TEST " << testCounter << endl;
    cout << "Test Connection Refused" << endl;

    gEventsCount = 0;
    gDumpedPackets = 0;

    Configuration::initialize();
    Configuration::getInstance().setConfiguredValues(configFileString);

    Configuration::getInstance().logsDirectory = LOG_DIR;

    std::list<uint32_t> ipBackSvcList;
    TestPCAPManager *pcapMgr = new TestPCAPManager();
    PacketSniffer *packetSniffer = new PacketSniffer();
    TestConnectorRefusedConn *testConnector = new TestConnectorRefusedConn();
    ProcessIdentifier *pIdentifierConn = new ProcessIdentifierLSOF();
    ProcessIdentifier *pIdentifierListen = new ProcessIdentifierLSOF();

    packetSniffer->initialize(*testConnector, *pcapMgr, *daemonLogging, pcapFilter, pcapDevice, ipBackSvcList, pIdentifierConn, pIdentifierListen, nullptr);

    threadSnifferAgent = new std::thread(PacketSniffer::runAgentThread, packetSniffer);

    cout << "ABOUT to enter loop" << endl;

    bool endLoop = false;

    while(!endLoop) {
        if (gEventsCount > 0 && gDumpedPackets > 1) break;
        std::this_thread::sleep_for(10s);
    }

    ASSERT_TRUE(gEventsCount == 1);
    ASSERT_TRUE(gReceivedEventConnRST == 1);
    ASSERT_TRUE(gDumpedPackets == 2);

    cout << "ABOUT to finish" << endl;

    packetSniffer->endSniffing();

    threadSnifferAgent->join();

    delete pcapMgr;
    delete testConnector;
    delete packetSniffer;
    delete threadSnifferAgent;
}


void executeManyConnectionsTests(uint16_t& testCounter) {
    std::thread *threadSnifferAgent;
    const char *filename = "./testfiles/test_ssl_3MBpcap.pcap";
    string pcapFilter = "tcp";
    string pcapDevice = filename;
    string configFileString = DEFAULT_CONFIG_FILE;

    testCounter++;
    cout << "....... TEST " << testCounter << endl;
    cout << "Test Many Connections" << endl;

    gEventsCount = 0;
    gDumpedPackets = 0;
    gReceivedEventConnRST = 0;

    Configuration::initialize();

    Configuration::getInstance().setConfiguredValues(configFileString);

    Configuration::getInstance().NoHTTPSClientSSLShutdownEvent = false;
    Configuration::getInstance().logsDirectory = LOG_DIR;
    Configuration::getInstance().NoHTTPClientResetEvent = false;

    std::list<uint32_t> ipBackSvcList;
    TestPCAPManager *pcapMgr = new Test_3MB_PCAPManager();
    PacketSniffer *packetSniffer = new PacketSniffer();
    TestConnectorRefusedConn *testConnector = new TestConnectorRefusedConn();
    ProcessIdentifier *pIdentifierConn = new ProcessIdentifierLSOF();
    ProcessIdentifier *pIdentifierListen = new ProcessIdentifierLSOF();

    packetSniffer->initialize(*testConnector, *pcapMgr, *daemonLogging, pcapFilter, pcapDevice, ipBackSvcList, pIdentifierConn, pIdentifierListen, nullptr);

    threadSnifferAgent = new std::thread(PacketSniffer::runAgentThread, packetSniffer);

    cout << "ABOUT to enter sleep 30s" << endl;

    std::this_thread::sleep_for(30s);

    ASSERT_EQ(gEventsCount, (uint32_t)1);
    ASSERT_EQ(gReceivedEventConnRST, 0);
    ASSERT_GT(gDumpedPackets, (uint32_t)0);

    cout << "ABOUT to finish" << endl;

    packetSniffer->endSniffing();

    threadSnifferAgent->join();

    delete pcapMgr;
    delete testConnector;
    delete packetSniffer;
    delete threadSnifferAgent;
}

void executeTLSCloseNotifyTests(uint16_t& testCounter) {
    std::thread *threadSnifferAgent;
    const char *filename = "./testfiles/test_close_notify.pcap";
    string pcapFilter = "tcp";
    string pcapDevice = filename;
    string configFileString = DEFAULT_CONFIG_FILE;

    testCounter++;
    cout << "....... TEST " << testCounter << endl;
    cout << "Test TLS Close Notify" << endl;

    gEventsCount = 0;
    gDumpedPackets = 0;
    gReceivedEventTLSConn = 0;
    gReceivedEventTLSAlert = 0;
    gReceivedEventStale = 0;

    Configuration::initialize();
    Configuration::getInstance().setConfiguredValues(configFileString);

    Configuration::getInstance().keepaliveThresholdStaleEstablished = 1;
    Configuration::getInstance().events_for_tls_connections = true;
    Configuration::getInstance().logsDirectory = LOG_DIR;

    std::list<uint32_t> ipBackSvcList;
    TestPCAPManager *pcapMgr = new TestPCAPManager();
    PacketSniffer *packetSniffer = new PacketSniffer();
    TestConnectorCloseNotify *testConnector = new TestConnectorCloseNotify();
    pcapMgr->finishedLoop = true;
    ProcessIdentifier *pIdentifierConn = new ProcessIdentifierLSOF();
    ProcessIdentifier *pIdentifierListen = new ProcessIdentifierLSOF();

    packetSniffer->initialize(*testConnector, *pcapMgr, *daemonLogging, pcapFilter, pcapDevice, ipBackSvcList, pIdentifierConn, pIdentifierListen, nullptr);

    threadSnifferAgent = new std::thread(PacketSniffer::runAgentThread, packetSniffer);

    cout << "ABOUT to enter loop" << endl;

    bool endLoop = false;
    while(!endLoop) {
        if (pcapMgr->finishedLoop) break;
        std::this_thread::sleep_for(2s);
    }
    std::this_thread::sleep_for(10s);

    ASSERT_EQ(gEventsCount, (uint32_t)1);
    ASSERT_EQ(gReceivedEventTLSConn, (uint8_t)1);
    ASSERT_EQ(gReceivedEventTLSAlert, (uint8_t)0);
    ASSERT_EQ(gDumpedPackets, (uint32_t)0);

    cout << "ABOUT to finish" << endl;

    packetSniffer->endSniffing();

    threadSnifferAgent->join();

    delete pcapMgr;
    delete testConnector;
    delete packetSniffer;
    delete threadSnifferAgent;
}


} //namespace connectionUnitTest

