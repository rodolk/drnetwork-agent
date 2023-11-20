/*
 * tlsUnitTest.cpp
 *
 *  Created on: Jul 6, 2021
 *      Author: rodolk
 */

#include <iostream>
#include <pcap.h>
#include <string.h>
#include <arpa/inet.h>
#include <gtest/gtest.h>

#include "skb.h"
#include "frameBuffer.h"
#include "frameStoreHandler.h"
#include "TLSInterpreter.h"
#include "common.h"

#define NUM_FRAME_BUFFER 500
//#define NUM_FRAME_BUFFER 10000

extern void resetEnvironment();
extern bool gEnvironmentReset;

namespace tlsUnitTest {

uint8_t gAlertCode = 0;
uint8_t gAlertSeverity = 0;
uint8_t gExceptionCode = 0;

using namespace std;

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
    uint16_t tcpIdx;
    //uint16_t datagramLen;
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

    pcap = pcap_open_offline(filename, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "error reading pcap file: %s\n", errbuf);
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


void executeTLSAlertTests(uint16_t& testCounter) {
    const char *filename = "./testfiles/test_tls_alert_cert_val.pcap";
    testCounter++;
    cout << "....... TEST " << testCounter << endl;
    cout << "Test TLS Alerts CA certificate" << endl;

    if (!gEnvironmentReset) {
        initializeSkb();
        FrameBuffer::initialize(NUM_FRAME_BUFFER);
    }

    gAlertSeverity = 0;
    gAlertCode = 0;
    gExceptionCode = 0;

    processPackets(filename);
    resetEnvironment();

    ASSERT_EQ(gAlertSeverity, 2);
    ASSERT_EQ(gExceptionCode, 1);
    ASSERT_EQ(gAlertCode, 48);

    //New test

    filename = "./testfiles/test_tls_alert_ciphers.pcap";
    testCounter++;
    cout << "....... TEST " << testCounter << endl;
    cout << "Test TLS Alerts ciphers" << endl;

    gAlertSeverity = 0;
    gAlertCode = 0;
    gExceptionCode = 0;

    processPackets(filename);
    resetEnvironment();

    ASSERT_EQ(gAlertSeverity, 2);
    ASSERT_EQ(gExceptionCode, 1);
    ASSERT_EQ(gAlertCode, 40);

    //New test

    filename = "./testfiles/test_tls_alert_internal_err.pcap";
    testCounter++;
    cout << "....... TEST " << testCounter << endl;
    cout << "Test TLS Alerts internal error" << endl;

    gAlertSeverity = 0;
    gAlertCode = 0;
    gExceptionCode = 0;

    processPackets(filename);
    resetEnvironment();

    ASSERT_EQ(gAlertSeverity, 2);
    ASSERT_EQ(gExceptionCode, 1);
    ASSERT_EQ(gAlertCode, 80);

}

} //namespace tlsUnitTest

