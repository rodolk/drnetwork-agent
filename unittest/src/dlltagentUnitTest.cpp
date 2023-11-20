//============================================================================
// Name        : dlltagentUnitTest.cpp
// Author      : Rodolfo Kohn
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================

#include <iostream>
#include <gtest/gtest.h>
#include <pcap.h>
#include <arpa/inet.h>

#include <unistd.h>

#include "skb.h"
#include "frameStoreHandler.h"
#include "frameBuffer.h"
#include "daemonLog.h"
#include "TCPSegmentIterator.h"
#include "TLSInterpreter.h"
#include "skbUnitTest.h"
#include "tlsUnitTest.h"
#include "connectionUnitTest.h"
#include "common.h"
#include "TestPCAPManager.h"
#include "Configuration.h"



#define LOG_FILENAME "log_notif_test"
#define LOG_DIR "./logs"
#define DEFAULT_CONFIG_FILE "./dllt.cfg"

using namespace std;

extern skb_t *listConnectingSkb;

DaemonLog *daemonLogging{nullptr};

bool gEnvironmentReset = false;


skb_t *currSkb;
int counter = 0;
const char *filename;

class UnitTestChecker {
public:
    TCPSegmentIterator *tcpSgmtIter;
    UnitTestChecker(TCPSegmentIterator *iter) : tcpSgmtIter(iter) {}
    uint32_t getNextOffset() {
        return tcpSgmtIter->framePtr_->offsetNext_;
    }
    uint32_t getLastOffset() {
        return tcpSgmtIter->framePtr_->offsetLast_;
    }
    uint32_t getFirstOffset() {
        return tcpSgmtIter->framePtr_->offsetFirst_;
    }
};



#define NUM_FRAME_BUFFER 500
//#define NUM_FRAME_BUFFER 10000

msg_buffer_t msgBuf;
msg_buffer_t msgBuf2;
msg_buffer_t msgBuf3;


void populateBaseFrameBuffers(const char *filename) {
    pcap_t *pcap;
    const unsigned char *packet;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    uint32_t msgLen;

    pcap = pcap_open_offline(filename, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "error reading pcap file: %s\n", errbuf);
        exit(1);
    }

    int i = 0;
    while ((packet = pcap_next(pcap, &header)) != NULL) {
        i++;
        msgLen = (header.caplen > MAX_MSG_LEN) ? MAX_MSG_LEN : header.caplen;
        memcpy(msgBuf.msg, packet, msgLen);
        memcpy(&msgBuf.hdr, &header, sizeof(struct pcap_pkthdr));
        msgBuf.status = 1;
        msgBuf.len = msgLen;
        if (i == 7) {
            memcpy(&msgBuf2, &msgBuf, sizeof(msgBuf));
        }
        if (i == 1) {
            memcpy(&msgBuf3, &msgBuf, sizeof(msgBuf));
        }
        currSkb = storePacket(&msgBuf);
    }
}

/**
 * FrameBuffer size is 1,048,576 Bytes.
 * Last packet in the pcap file test3.pcap is 2289 Bytes, adding 28 Bytes it's 2317 Bytes.
 * Previous 7 packets + 28 Bytes for each is: 2519
 * So we can have 451 packets equal to the last packet and everything will occupy 1,044,967 Bytes
 * Packet equal-to-last number 452 will occupy 1090 Bytes of this FrameBuffer and
 *  1,227 in the next FrameBuffer.
 *  1,048,576 - 2,519 - (2,317 * 451) = (1,044,967 + 1,090)
 *  2,317 - 1,090 = 1,227
 *
 */
void populateFrameBuffersCompleteFrameBuffer(const char *filename) {
    int i;

    memset(&msgBuf, 0, sizeof(msg_buffer_t));
    memset(&msgBuf2, 0, sizeof(msg_buffer_t));
    memset(&msgBuf3, 0, sizeof(msg_buffer_t));

    populateBaseFrameBuffers(filename);

    //Store 451 more. The last one will be part in the current FrameBuffer and part in the next one.
    for(i = 0; i < 451; i++) {
        storePacket(&msgBuf);
    }
}

/**
 * Here we complete a frame buffer and at the end there are only 24 Bytes left.
 * In the next FrameBuffer we have a packet with no payload and then one with payload.
 * FrameBuffer size is 1,048,576 Bytes.
 * Last packet in the pcap file test3.pcap is 2289 Bytes, adding 28 Bytes it's 2317 Bytes.
 * Previous 7 packets + 28 Bytes for each is: 2519
 * So we can have 451 packets equal to the last packet and everything will occupy 1,044,967 Bytes
 * Packet equal-to-last number 452 will occupy 1090 Bytes of this FrameBuffer and
 *  1,227 in the next FrameBuffer.
 *  1,048,576 - 2,519 - (2,317 * 451) = (1,044,967 + 1,090)
 *  2,317 - 1,090 = 1,227
 *
 */
void populateFrameBuffersCompleteFrameBuffer2(const char *filename) {
    int i;

    memset(&msgBuf, 0, sizeof(msg_buffer_t));
    memset(&msgBuf2, 0, sizeof(msg_buffer_t));
    memset(&msgBuf3, 0, sizeof(msg_buffer_t));

    populateBaseFrameBuffers(filename);

    //Store 450 more. At the end we have 1,090 Bytes left.
    for(i = 0; i < 450; i++) {
        storePacket(&msgBuf);
    }
    //After the 13th packet there should be only 24 Bytes left
    //The 14th goes to the next FrameBuffer
    for(i = 0; i < 14; i++) {
        storePacket(&msgBuf2);
    }
    //Finally one with data
    storePacket(&msgBuf);
}


void populateFrameBuffersCompleteFrameBuffer3(const char *filename) {
    int i;

    memset(&msgBuf, 0, sizeof(msg_buffer_t));
    memset(&msgBuf2, 0, sizeof(msg_buffer_t));
    memset(&msgBuf3, 0, sizeof(msg_buffer_t));

    populateBaseFrameBuffers(filename);

    //Store 450 more. At the end we have 1,090 Bytes left.
    for(i = 0; i < 450; i++) {
        storePacket(&msgBuf);
    }
    //7 packets of 74 Bytes + 28 Bytes
    for(i = 0; i < 7; i++) {
        storePacket(&msgBuf3);
    }
    //4 packets of 54 Bytes + 28 Bytes
    for(i = 0; i < 4; i++) {
        storePacket(&msgBuf2);
    }
    //48 Bytes left in this FrameBuffer
    //Add 1 packet of 54 + 28 Bytes. This packet should occupy all space left in this FrameBuffer
    //and part of the next FrameBuffer
    storePacket(&msgBuf2);
    //Finally one with data
    storePacket(&msgBuf);
}


void populateFrameBuffersCompleteFrameBuffer4(const char *filename, uint16_t lastSpaceLen, int testcase) {
    msg_buffer_t msgBuf4;
    int i;

    memset(&msgBuf, 0, sizeof(msg_buffer_t));
    memset(&msgBuf2, 0, sizeof(msg_buffer_t));
    memset(&msgBuf3, 0, sizeof(msg_buffer_t));

    populateBaseFrameBuffers(filename);

    //Store 450 more. At the end we have 1,090 Bytes left.
    for(i = 0; i < 450; i++) {
        storePacket(&msgBuf);
    }
    //7 packets of 74 Bytes + 28 Bytes
    for(i = 0; i < 7; i++) {
        storePacket(&msgBuf3);
    }
    //2 packets of 54 Bytes + 28 Bytes
    for(i = 0; i < 2; i++) {
        storePacket(&msgBuf2);
    }

    memcpy(&msgBuf4, &msgBuf2, sizeof(msgBuf2));
    *((uint16_t *)&msgBuf4.msg[16]) = htons(212 - 14 - lastSpaceLen);
    memset(&msgBuf4.msg[54], '1', (212 - 54 - lastSpaceLen));
    msgBuf4.len = (212 - 28 - lastSpaceLen);
    msgBuf4.hdr.caplen = (212 - 28 - lastSpaceLen);
    msgBuf4.hdr.len = (212 - 28 - lastSpaceLen);

    storePacket(&msgBuf4);

    if (testcase == 0) {
        //(lastSpaceLen) Bytes left in this FrameBuffer
        //Add 1 packet of 54 + 28 Bytes. This packet should occupy all space left in this FrameBuffer
        //and part of the next FrameBuffer
        storePacket(&msgBuf2);
    }
    //Finally one with data
    storePacket(&msgBuf);
}

void populateFrameBuffersCompleteFrameBuffer5(const char *filename, uint16_t lastSpaceLen) {
    msg_buffer_t msgBuf4;
    int i;

    memset(&msgBuf, 0, sizeof(msg_buffer_t));
    memset(&msgBuf2, 0, sizeof(msg_buffer_t));
    memset(&msgBuf3, 0, sizeof(msg_buffer_t));

    populateBaseFrameBuffers(filename);

    //Store 450 more. At the end we have 1,090 Bytes left.
    for(i = 0; i < 450; i++) {
        storePacket(&msgBuf);
    }
    //7 packets of 74 Bytes + 28 Bytes
    for(i = 0; i < 7; i++) {
        storePacket(&msgBuf3);
    }
    //2 packets of 54 Bytes + 28 Bytes
    for(i = 0; i < 2; i++) {
        storePacket(&msgBuf2);
    }

    memcpy(&msgBuf4, &msgBuf2, sizeof(msgBuf2));
    *((uint16_t *)&msgBuf4.msg[16]) = htons(212 - 14 - lastSpaceLen);
    memset(&msgBuf4.msg[54], '1', (212 - 54 - lastSpaceLen));
    msgBuf4.len = (212 - 28 - lastSpaceLen);
    msgBuf4.hdr.caplen = (212 - 28 - lastSpaceLen);
    msgBuf4.hdr.len = (212 - 28 - lastSpaceLen);

    storePacket(&msgBuf4);
}


/*
 * FrameBuffer size is 1,048,576 Bytes.
 * Last packet in the pcap file test3.pcap is 2289 Bytes, adding 28 Bytes it's 2317 Bytes.
 */

void populateFrameBuffersWrapAround(const char *filename) {
    int i;

    populateFrameBuffersCompleteFrameBuffer(filename);

    /*
     * In next FrameBuffer we have written 1,227 Bytes.
     * There are (1,048,576 - 1,227 = 1,047,349) Bytes left.
     * Now continue populating next FrameBuffer. FrameBuffer 2.
     * msgBuf contains 2,289 packet Bytes. Then for each one we store a total of 2,317 B
     * 2,317 * 451 = 1,044,967
     * 1,048,576 - 1,044,967 - 1,227 = 2,382
     *
     *
     */

    for(i = 0; i < 451; i++) {
        storePacket(&msgBuf);
    }

    // 2,382 Bytes left in second Frame Buffer
}

bool gTestsInitialized = false;

void initializeTests() {
    const char *logFile = LOG_FILENAME;
    bool foreground = true;
    DaemonLog::eLOGLevel logLevel = DaemonLog::LOGLevelDebug;
    string configFileString = DEFAULT_CONFIG_FILE;

    Configuration::initialize();
    Configuration& config = Configuration::getInstance();

    config.setConfiguredValues(configFileString);

    cout << "Logs directory: " << config.logsDirectory << endl;

    daemonLogging = new DaemonLog();
    if (!foreground)
    {
        daemonLogging->initialize(LOG_DIR, logFile);
    }
    else
    {
        daemonLogging->initialize();
    }
    daemonLogging->setLogLevel(logLevel);
    ApplicationLog::setLog(daemonLogging);
    gTestsInitialized = true;

}

void checkFrameBuffers() {
    TCPSegmentIterator *tcpSgmtIter = new TCPSegmentIterator(currSkb);
    uint32_t offsetIdx = tcpSgmtIter->getOffsetLastSegment();
    cout << "Offset Last Segment: " << offsetIdx << endl;
    uint32_t expectedIdx = 909 + 28;
    ASSERT_TRUE(offsetIdx == expectedIdx);

    delete tcpSgmtIter;
}

void test1() {
    checkFrameBuffers();
    skb_t *currentSkb = listConnectingSkb;
    ASSERT_TRUE(currentSkb->used == 4);
}

static void readFirstTenTCPPayloadBytes(TCPSegmentIterator *tcpSgmtIter) {
    uint16_t len = 10;
    bool moreDataAvailable;
    const uint8_t *data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
    ASSERT_TRUE(moreDataAvailable);
    ASSERT_TRUE(len == 0);
    ASSERT_TRUE(data == nullptr);
    len = 10;
    data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
    ASSERT_TRUE(moreDataAvailable);
    ASSERT_TRUE(len == 10);
    ASSERT_TRUE(data != nullptr);
    cout << "data[0]: " << (unsigned int)data[0] << endl;
    ASSERT_TRUE(data[0] == 0x16);
}

TCPSegmentIterator *getTCPSegmentIterator(skb_t *skb) {
    TCPSegmentIterator *tcpSgmtIter = new TCPSegmentIterator(currSkb);
    tcpSgmtIter->initialize();
    return tcpSgmtIter;
}
UnitTestChecker *getUnitTestChecker(TCPSegmentIterator *tcpSgmtIter) {
    UnitTestChecker *utChecker = new UnitTestChecker(tcpSgmtIter);

    return utChecker;
}

void checkOffsets(UnitTestChecker *utChecker, uint32_t firstOffset, uint32_t nextOffset, uint32_t lastOffset) {
    cout << "firstOffset: " << (unsigned int)utChecker->getFirstOffset() << endl;
    cout << "nextOffset: " << (unsigned int)utChecker->getNextOffset() << endl;
    cout << "lastOffset: " << (unsigned int)utChecker->getLastOffset() << endl;

    ASSERT_TRUE(utChecker->getFirstOffset() == firstOffset);
    ASSERT_TRUE(utChecker->getNextOffset() == nextOffset);
    ASSERT_TRUE(utChecker->getLastOffset() == lastOffset);
}




void processFirstPart(TCPSegmentIterator *tcpSgmtIter, bool lastDataAVailable=true) {
    readFirstTenTCPPayloadBytes(tcpSgmtIter);

    uint16_t len = 6000;
    bool moreDataAvailable = false;
    const uint8_t *data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
    cout << "len: " << (unsigned int)len << endl;
    ASSERT_TRUE(moreDataAvailable);
    ASSERT_TRUE(len == 507);
    ASSERT_TRUE(data != nullptr);
    cout << "data[0]: " << (unsigned int)data[0] << endl;
    ASSERT_TRUE(data[0] == 0x03);

    len = 6000;
    moreDataAvailable = false;
    data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
    cout << "len: " << (unsigned int)len << endl;
    ASSERT_TRUE(moreDataAvailable);
    ASSERT_TRUE(len == 1396);
    ASSERT_TRUE(data != nullptr);

    len = 6000;
    moreDataAvailable = !lastDataAVailable;
    data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
    cout << "len: " << (unsigned int)len << endl;
    ASSERT_TRUE(moreDataAvailable == lastDataAVailable);
    ASSERT_TRUE(len == 2235);
    ASSERT_TRUE(data != nullptr);

}

void processSecondPart(TCPSegmentIterator *tcpSgmtIter) {
    int i;
    uint16_t len;
    bool moreDataAvailable;
    const uint8_t *data;

    for (i = 0; i < 450; i++) {
        len = 6000;
        moreDataAvailable = false;
        data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
        ASSERT_TRUE(moreDataAvailable);
        ASSERT_TRUE(len == 2235);
        ASSERT_TRUE(data != nullptr);
    }
}


void test2() {
    TCPSegmentIterator *tcpSgmtIter = new TCPSegmentIterator(currSkb);
    tcpSgmtIter->initialize();
    readFirstTenTCPPayloadBytes(tcpSgmtIter);

    delete tcpSgmtIter;
}

void test3() {
    TCPSegmentIterator *tcpSgmtIter = new TCPSegmentIterator(currSkb);
    tcpSgmtIter->initialize();
    readFirstTenTCPPayloadBytes(tcpSgmtIter);

    uint16_t len = 600;
    bool moreDataAvailable;
    const uint8_t *data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
    cout << "len: " << (unsigned int)len << endl;
    ASSERT_TRUE(!moreDataAvailable);
    ASSERT_TRUE(len == 507);
    ASSERT_TRUE(data != nullptr);
    cout << "data[0]: " << (unsigned int)data[0] << endl;
    ASSERT_TRUE(data[0] == 0x03);

    len = 1;
    moreDataAvailable = true;
    data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
    cout << "len: " << (unsigned int)len << endl;
    ASSERT_TRUE(!moreDataAvailable);
    ASSERT_TRUE(len == 0);
    ASSERT_TRUE(data == nullptr);

    len = 20000;
    moreDataAvailable = true;
    data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
    cout << "len: " << (unsigned int)len << endl;
    ASSERT_TRUE(!moreDataAvailable);
    ASSERT_TRUE(len == 0);
    ASSERT_TRUE(data == nullptr);

    len = 0;
    moreDataAvailable = true;
    data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
    cout << "len: " << (unsigned int)len << endl;
    ASSERT_TRUE(!moreDataAvailable);
    ASSERT_TRUE(len == 0);
    ASSERT_TRUE(data == nullptr);

    delete tcpSgmtIter;
}

void test4(int testcase = 0) {
    uint16_t len;
    bool moreDataAvailable;
    const uint8_t *data;
    int i;
    TCPSegmentIterator *tcpSgmtIter = getTCPSegmentIterator(currSkb);
    UnitTestChecker *utChecker = getUnitTestChecker(tcpSgmtIter);

    checkOffsets(utChecker, 0, 4836, 2519);

    processFirstPart(tcpSgmtIter, false);

    for (i=0;i<3;i++) {
        len = 6000;
        moreDataAvailable = true;
        data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
        ASSERT_TRUE(!moreDataAvailable);
        ASSERT_TRUE(len == 0);
        ASSERT_TRUE(data == nullptr);
    }

    if (testcase == 1) {
        //msgBuf stayed intact from the population of packets
        storePacket(&msgBuf2);

        len = 2235;
        moreDataAvailable = true;
        data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
        cout << "len: " << (unsigned int)len << endl;
        ASSERT_TRUE(!moreDataAvailable);
        ASSERT_TRUE(len == 0);
        ASSERT_TRUE(data == nullptr);

        storePacket(&msgBuf);

        len = 2235;
        moreDataAvailable = false;
        data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
        cout << "len: " << (unsigned int)len << endl;
        ASSERT_TRUE(moreDataAvailable);
        ASSERT_TRUE(len == 0);
        ASSERT_TRUE(data == nullptr);

        len = 2235;
        moreDataAvailable = true;
        data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
        cout << "len: " << (unsigned int)len << endl;
        ASSERT_TRUE(!moreDataAvailable);
        ASSERT_TRUE(len == 2235);
        ASSERT_TRUE(data != nullptr);

        checkOffsets(utChecker, 0, 4836 + (54 + 28) + (2289 + 28), 4836 + (54 + 28));
    }

    delete utChecker;
    delete tcpSgmtIter;
}


void test5() {
    TCPSegmentIterator *tcpSgmtIter = getTCPSegmentIterator(currSkb);
    UnitTestChecker *utChecker = getUnitTestChecker(tcpSgmtIter);

    checkOffsets(utChecker, 0, (1024 * 1024), (1024 * 1024 - 1090));
    processFirstPart(tcpSgmtIter);
    processSecondPart(tcpSgmtIter);

    uint16_t len = 2000;
    bool moreDataAvailable = false;
    const uint8_t *data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
    cout << "len: " << (unsigned int)len << endl;
    ASSERT_TRUE(moreDataAvailable);
    ASSERT_TRUE(len == 1090-54-28); //54 is the ETHER, IP HEADER and TCP HEADER - 28 is uint32_t + pkthdr
    ASSERT_TRUE(data != nullptr);


    len = 6000;
    moreDataAvailable = true;
    data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
    cout << "len: " << (unsigned int)len << endl;
    ASSERT_TRUE(!moreDataAvailable);
    ASSERT_TRUE(len == 1227); //1227 payload bytes in next FrameBuffer, at offset 0 packet num 0
    ASSERT_TRUE(data != nullptr);

    checkOffsets(utChecker, 1227, 1227, 0);

    delete utChecker;
    delete tcpSgmtIter;
}



void test6() {
    TCPSegmentIterator *tcpSgmtIter = getTCPSegmentIterator(currSkb);
    UnitTestChecker *utChecker = getUnitTestChecker(tcpSgmtIter);

    checkOffsets(utChecker, 0, (1024 * 1024) - 24, (1024 * 1024 - 24 - 82));

    processFirstPart(tcpSgmtIter);
    processSecondPart(tcpSgmtIter);

    uint16_t len = 2000;
    bool moreDataAvailable = false;
    const uint8_t *data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
    cout << "len: " << (unsigned int)len << endl;
    ASSERT_TRUE(moreDataAvailable);
    ASSERT_TRUE(len == 2000);
    ASSERT_TRUE(data != nullptr);

    len = 2000;
    moreDataAvailable = false;
    data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
    cout << "len: " << (unsigned int)len << endl;
    ASSERT_TRUE(!moreDataAvailable);
    ASSERT_TRUE(len == 235);
    ASSERT_TRUE(data != nullptr);

    checkOffsets(utChecker, 0,
            (54 + 28 + 2289 + 28),
            (54 + 28));

    delete utChecker;
    delete tcpSgmtIter;
}


void test7() {
    TCPSegmentIterator *tcpSgmtIter = getTCPSegmentIterator(currSkb);
    UnitTestChecker *utChecker = getUnitTestChecker(tcpSgmtIter);

    checkOffsets(utChecker, 0, (1024 * 1024), (1024 * 1024 - 48));

    processFirstPart(tcpSgmtIter);
    processSecondPart(tcpSgmtIter);

    uint16_t len = 2000;
    bool moreDataAvailable = false;
    const uint8_t *data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
    cout << "len: " << (unsigned int)len << endl;
    ASSERT_TRUE(moreDataAvailable);
    ASSERT_TRUE(len == 2000);
    ASSERT_TRUE(data != nullptr);

    len = 2000;
    moreDataAvailable = true;
    data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
    cout << "len: " << (unsigned int)len << endl;
    ASSERT_TRUE(!moreDataAvailable);
    ASSERT_TRUE(len == 235);
    ASSERT_TRUE(data != nullptr);

    checkOffsets(utChecker, (82-48), ((82-48) + 2289 + 28), (82-48));

    delete utChecker;
    delete tcpSgmtIter;
}


void test8(uint16_t lastSpaceLeft, int testcase = 0) {
    TCPSegmentIterator *tcpSgmtIter = getTCPSegmentIterator(currSkb);
    UnitTestChecker *utChecker = getUnitTestChecker(tcpSgmtIter);

    checkOffsets(utChecker, 0,
            ((lastSpaceLeft == 28)? (1024 * 1024) - 28 : (1024 * 1024)),
            ((lastSpaceLeft == 28)? (1024 * 1024) - (212): (1024 * 1024) - lastSpaceLeft));

    processFirstPart(tcpSgmtIter);
    processSecondPart(tcpSgmtIter);

    uint16_t len = 2000;
    bool moreDataAvailable = false;
    const uint8_t *data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
    //cout << "len: " << (unsigned int)len << endl;
    ASSERT_TRUE(moreDataAvailable);
    ASSERT_TRUE(len == (212 - 28 - lastSpaceLeft - 54));
    ASSERT_TRUE(data != nullptr);

    len = 2000;
    moreDataAvailable = false;
    data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
    //cout << "len: " << (unsigned int)len << endl;
    ASSERT_TRUE(moreDataAvailable);
    ASSERT_TRUE(len == 2000);
    ASSERT_TRUE(data != nullptr);

    len = 2000;
    moreDataAvailable = true;
    data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
    //cout << "len: " << (unsigned int)len << endl;
    ASSERT_TRUE(!moreDataAvailable);
    ASSERT_TRUE(len == 235);
    ASSERT_TRUE(data != nullptr);

    checkOffsets(utChecker, ((lastSpaceLeft == 28) ? 0 : (54 - (lastSpaceLeft - 28))),
            ((lastSpaceLeft == 28) ? (2289 + 28 + 54 + 28) : (54 - (lastSpaceLeft - 28)) + (2289 + 28)),
            ((lastSpaceLeft == 28) ? (54 + 28) : (54 - (lastSpaceLeft - 28))));

    if (testcase == 1) {
        //msgBuf stayed intact from the population of packets
        storePacket(&msgBuf);

        len = 2235;
        moreDataAvailable = true;
        data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
        cout << "len: " << (unsigned int)len << endl;
        ASSERT_TRUE(moreDataAvailable);
        ASSERT_TRUE(len == 0);
        ASSERT_TRUE(data == nullptr);

        len = 2235;
        moreDataAvailable = true;
        data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
        cout << "len: " << (unsigned int)len << endl;
        ASSERT_TRUE(!moreDataAvailable);
        ASSERT_TRUE(len == 2235);
        ASSERT_TRUE(data != nullptr);

        checkOffsets(utChecker, ((lastSpaceLeft == 28) ? 0 : (54 - (lastSpaceLeft - 28))),
                ((lastSpaceLeft == 28) ? (54 + 28) + 2 *(2289 + 28) : (54 - (lastSpaceLeft - 28)) + 2 * (2289 + 28)),
                ((lastSpaceLeft == 28) ? (54 + 28) + (2289 + 28): (54 - (lastSpaceLeft - 28)) + (2289 + 28)));
    }

    delete utChecker;
    delete tcpSgmtIter;
}

void test9(uint16_t lastSpaceLeft, int testcase = 0) {
    TCPSegmentIterator *tcpSgmtIter = getTCPSegmentIterator(currSkb);
    UnitTestChecker *utChecker = getUnitTestChecker(tcpSgmtIter);

    checkOffsets(utChecker, 0,
            ((lastSpaceLeft == 28)? (1024 * 1024) - 28 : (1024 * 1024)),
            ((lastSpaceLeft == 28)? (1024 * 1024) - (212): (1024 * 1024) - lastSpaceLeft));

    processFirstPart(tcpSgmtIter);
    processSecondPart(tcpSgmtIter);

    uint16_t len = 2000;
    bool moreDataAvailable = false;
    const uint8_t *data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
    //cout << "len: " << (unsigned int)len << endl;
    ASSERT_TRUE(moreDataAvailable);
    ASSERT_TRUE(len == (212 - 28 - lastSpaceLeft - 54));
    ASSERT_TRUE(data != nullptr);

    len = 2000;
    moreDataAvailable = false;
    data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
    //cout << "len: " << (unsigned int)len << endl;
    ASSERT_TRUE(moreDataAvailable);
    ASSERT_TRUE(len == 2000);
    ASSERT_TRUE(data != nullptr);

    len = 2000;
    moreDataAvailable = true;
    data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
    //cout << "len: " << (unsigned int)len << endl;
    ASSERT_TRUE(!moreDataAvailable);
    ASSERT_TRUE(len == 235);
    ASSERT_TRUE(data != nullptr);

    checkOffsets(utChecker, ((lastSpaceLeft == 28) ? 0 : (2289 - (lastSpaceLeft - 28))),
            ((lastSpaceLeft == 28) ? (2289 + 28) : (2289 - (lastSpaceLeft - 28))),
            0);

    if (testcase == 1) {
        //msgBuf stayed intact from the population of packets
        storePacket(&msgBuf);

        len = 2235;
        moreDataAvailable = true;
        data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
        ASSERT_TRUE(moreDataAvailable);
        ASSERT_TRUE(len == 0);
        ASSERT_TRUE(data == nullptr);

        len = 2235;
        moreDataAvailable = true;
        data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
        ASSERT_TRUE(!moreDataAvailable);
        ASSERT_TRUE(len == 2235);
        ASSERT_TRUE(data != nullptr);

        checkOffsets(utChecker, ((lastSpaceLeft == 28) ? 0 : (2289 - (lastSpaceLeft - 28))),
                ((lastSpaceLeft == 28) ? (2289 + 28) + (2289 + 28) : (2289 - (lastSpaceLeft - 28)) + (2289 + 28)),
                ((lastSpaceLeft == 28) ? (2289 + 28) : (2289 - (lastSpaceLeft - 28))));

        //msgBuf stayed intact from the population of packets
        storePacket(&msgBuf);

        len = 2235;
        moreDataAvailable = true;
        data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
        ASSERT_TRUE(moreDataAvailable);
        ASSERT_TRUE(len == 0);
        ASSERT_TRUE(data == nullptr);

        len = 2235;
        moreDataAvailable = true;
        data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
        ASSERT_TRUE(!moreDataAvailable);
        ASSERT_TRUE(len == 2235);
        ASSERT_TRUE(data != nullptr);

        checkOffsets(utChecker, ((lastSpaceLeft == 28) ? 0 : (2289 - (lastSpaceLeft - 28))),
                ((lastSpaceLeft == 28) ? (2289 + 28) + 2 * (2289 + 28) : (2289 - (lastSpaceLeft - 28)) + 2 * (2289 + 28)),
                ((lastSpaceLeft == 28) ? (2289 + 28) + (2289 + 28) : (2289 - (lastSpaceLeft - 28)) + (2289 + 28)));
    }

    delete utChecker;
    delete tcpSgmtIter;
}

void test10(uint16_t lastSpaceLeft) {
    TCPSegmentIterator *tcpSgmtIter = getTCPSegmentIterator(currSkb);
    UnitTestChecker *utChecker = getUnitTestChecker(tcpSgmtIter);

    checkOffsets(utChecker, 0, (1024 * 1024) - lastSpaceLeft, (1024 * 1024) - (212));

    processFirstPart(tcpSgmtIter);
    processSecondPart(tcpSgmtIter);

    uint16_t len = 2000;
    bool moreDataAvailable = false;
    const uint8_t *data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
    //cout << "len: " << (unsigned int)len << endl;
    ASSERT_TRUE(!moreDataAvailable);
    ASSERT_TRUE(len == (212 - 28 - lastSpaceLeft - 54));
    ASSERT_TRUE(data != nullptr);

    len = 2000;
    moreDataAvailable = false;
    data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
    //cout << "len: " << (unsigned int)len << endl;
    ASSERT_TRUE(!moreDataAvailable);
    ASSERT_TRUE(len == 0);
    ASSERT_TRUE(data == nullptr);


    //msgBuf stayed intact from the population of packets
    storePacket(&msgBuf);

    len = 2235;
    moreDataAvailable = true;
    data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
    ASSERT_TRUE(moreDataAvailable);
    ASSERT_TRUE(len == 0);
    ASSERT_TRUE(data == nullptr);

    if (lastSpaceLeft < (28 + 54 + 1)) {
        len = 2235;
        moreDataAvailable = true;
        data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
        ASSERT_TRUE(!moreDataAvailable);
        ASSERT_TRUE(len == 2235);
        ASSERT_TRUE(data != nullptr);
    } else {
        len = 2235;
        moreDataAvailable = true;
        data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
        ASSERT_TRUE(moreDataAvailable);
        ASSERT_TRUE(len == lastSpaceLeft - (28 + 54));
        ASSERT_TRUE(data != nullptr);

        len = 2235;
        moreDataAvailable = true;
        data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
        ASSERT_TRUE(!moreDataAvailable);
        ASSERT_TRUE(len == 2235 - (lastSpaceLeft - (28 + 54)));
        ASSERT_TRUE(data != nullptr);

        len = 2235;
        moreDataAvailable = true;
        data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
        ASSERT_TRUE(!moreDataAvailable);
        ASSERT_TRUE(len == 0);
        ASSERT_TRUE(data == nullptr);
    }

    cout << "lastSpaceLeft: " << lastSpaceLeft << endl;
    checkOffsets(utChecker, ((lastSpaceLeft < 29) ? 0 : (2289 - (lastSpaceLeft - 28))),
            ((lastSpaceLeft < 29) ? (2289 + 28) : (2289 - (lastSpaceLeft - 28))),
            0);

    delete utChecker;
    delete tcpSgmtIter;
}


void test11() {
    TCPSegmentIterator *tcpSgmtIter = getTCPSegmentIterator(currSkb);
    UnitTestChecker *utChecker = getUnitTestChecker(tcpSgmtIter);

    checkOffsets(utChecker, 0, (1024 * 1024), (1024 * 1024) - 1090);
    processFirstPart(tcpSgmtIter);
    processSecondPart(tcpSgmtIter);

    //Next one spans to the next FrameBuffer
    uint16_t len = 6000;
    bool moreDataAvailable = false;
    const uint8_t *data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
    cout << "len: " << (unsigned int)len << endl;
    ASSERT_TRUE(moreDataAvailable);
    ASSERT_TRUE(len == 1090 - 54 - 28);
    ASSERT_TRUE(data != nullptr);

    //Next part
    len = 6000;
    moreDataAvailable = false;
    data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
    cout << "len: " << (unsigned int)len << endl;
    ASSERT_TRUE(moreDataAvailable);
    ASSERT_TRUE(len == 2235 - (1090 - 54 - 28));
    ASSERT_TRUE(data != nullptr);

    int i;
    for (i = 0; i < 450; i++) {
        len = 6000;
        moreDataAvailable = false;
        data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
        ASSERT_TRUE(moreDataAvailable);
        ASSERT_TRUE(len == 2235);
        ASSERT_TRUE(data != nullptr);
    }

    len = 6000;
    moreDataAvailable = false;
    data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
    cout << "len: " << (unsigned int)len << endl;
    ASSERT_TRUE(!moreDataAvailable);
    ASSERT_TRUE(len == 2235);
    ASSERT_TRUE(data != nullptr);

    checkOffsets(utChecker, 2235 - (1090 - 54 - 28), (1024 * 1024) - 2382, (1024 * 1024) - 2382 - 2317);

    /*
     * msgBuf stayed intact from the population of packets
     * We are adding 2,317 Bytes
     */
    storePacket(&msgBuf);

    //Now there are (2,382 - 2,317) = 65 Bytes left in the second FrameBuffer

    checkOffsets(utChecker, 2235 - (1090 - 54 - 28), (1024 * 1024) - 65, (1024 * 1024) - 65 - 2317);

    len = 6000;
    moreDataAvailable = false;
    data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
    cout << "len: " << (unsigned int)len << endl;
    ASSERT_TRUE(moreDataAvailable);
    ASSERT_TRUE(len == 0);
    ASSERT_TRUE(data == nullptr);

    len = 6000;
    moreDataAvailable = false;
    data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
    cout << "len: " << (unsigned int)len << endl;
    ASSERT_TRUE(!moreDataAvailable);
    ASSERT_TRUE(len == 2235);
    ASSERT_TRUE(data != nullptr);

    checkOffsets(utChecker, 2235 - (1090 - 54 - 28), (1024 * 1024) - 65, (1024 * 1024) - 65 - 2317);

    /*
     * There are 65 Bytes left in the second FrameBuffer
     * msgBuf stayed intact from the population of packets
     * We are adding 2,317 Bytes
     * 2,317 - 65 = 2,252 Bytes written in 3rd FrameBuffer
     */
    storePacket(&msgBuf);

    checkOffsets(utChecker, 2235 - (1090 - 54 - 28), (1024 * 1024), (1024 * 1024) - 65);

    len = 6000;
    moreDataAvailable = false;
    data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
    cout << "len: " << (unsigned int)len << endl;
    ASSERT_TRUE(moreDataAvailable);
    ASSERT_TRUE(len == 0);
    ASSERT_TRUE(data == nullptr);

    //We begin to read 3rd FB and read the whole data for the first packet that continues from 2nd FB
    len = 6000;
    moreDataAvailable = false;
    data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
    cout << "len: " << (unsigned int)len << endl;
    ASSERT_TRUE(!moreDataAvailable);
    ASSERT_TRUE(len == 2235);
    ASSERT_TRUE(data != nullptr);

    checkOffsets(utChecker, 2317 - 65, 2317 - 65, 0);

    for(i = 0; i < 451; i++) {
        storePacket(&msgBuf);
    }

    /*
     *
     * 2,317 * 451 = 1,044,967
     * 1,044,967 + 2,252 = 1,047,219 Bytes occupied in 3rd FB
     * 1,048,576 - 1,047,219 = 1,357 Bytes empty in 3rd FB
     *
     *
     */

    //We're reading in 3rd FB
    checkOffsets(utChecker, 2317 - 65, (1024 * 1024) - 1357, (1024 * 1024) - 1357 - 2317);

    /*
     * Next buffer to store wraps around coming from 3rd FB and continues in 2nd FB (not 1st FB)
     * Then we have 0 Bytes left in 3rd FB and
     * 2,317 - 1,357 = 960 Bytes used in 2nd FB
     *
     */
    storePacket(&msgBuf);

    checkOffsets(utChecker, 2317 - 65, (1024 * 1024), (1024 * 1024) - 1357);

    len = 6000;
    moreDataAvailable = false;
    data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
    ASSERT_TRUE(moreDataAvailable);
    ASSERT_TRUE(len == 0);
    ASSERT_TRUE(data == nullptr);

    for (i = 0; i < 451; i++) {
        len = 6000;
        moreDataAvailable = false;
        data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
        ASSERT_TRUE(moreDataAvailable);
        ASSERT_TRUE(len == 2235);
        ASSERT_TRUE(data != nullptr);
    }
    cout << endl;

    len = 6000;
    moreDataAvailable = false;
    data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
    cout << "len: " << (unsigned int)len << endl;
    ASSERT_TRUE(moreDataAvailable);
    ASSERT_TRUE(len == (1357 - (54 + 28)));
    ASSERT_TRUE(data != nullptr);

    /*
     * Now we wrapped around and begin to read data in the 2nd FB
     * We should have 960 Bytes of data in the continuing packet
     *
     */

    checkOffsets(utChecker, 960, 960, 0);

    len = 6000;
    moreDataAvailable = false;
    data = tcpSgmtIter->getTCPSegmentData(len, moreDataAvailable);
    cout << "len: " << (unsigned int)len << endl;
    ASSERT_TRUE(!moreDataAvailable);
    ASSERT_TRUE(len == 960);
    ASSERT_TRUE(data != nullptr);

    delete utChecker;
    delete tcpSgmtIter;
}


void cleanConnectingSkbList() {
    skb_t *currentSkb;
    skb_t *nextSkb;

    currentSkb = listConnectingSkb;

    while(currentSkb) {
        nextSkb = currentSkb->next;
        FrameStoreHandler::getInstance()->deleteFrameBufferList(currentSkb);
        delete currentSkb->tlsInterpreter;
        cout << "VALUE currentSkb->used: " << (int)currentSkb->used << endl;
        currentSkb->used = 0;
        submitDeleteConnectingSkb(currentSkb);
        currentSkb = nextSkb;
    }
}


void resetEnvironment() {
    cleanConnectingSkbList();
    shutdownSkb();
    FrameBuffer::shutdown();
    initializeSkb();
    FrameBuffer::initialize(NUM_FRAME_BUFFER);
    gEnvironmentReset = true;
}

TEST(FrameBuffer, AllCasesFrameBuffer_fast) {
    uint16_t testCounter = 1;
    cout << "*********************** BEGIN TESTS ***************************" << endl;
    initializeTests();

    char cwd[2000];
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        printf("Current working dir: %s\n", cwd);
    } else {
        perror("getcwd() error");
        return;
    }

    initializeSkb();
    FrameBuffer::initialize(NUM_FRAME_BUFFER);


    filename = "./testfiles/test1.pcap";
    populateBaseFrameBuffers(filename);
    cout << "....... TEST " << testCounter << endl;
    test1();

    testCounter++;
    cout << "....... TEST " << testCounter << endl;
    test2();

    testCounter++;
    cout << "....... TEST " << testCounter << endl;
    test3();
    resetEnvironment();

    cout << "--- NEW TEST SET: a few different packets and execute different-size read operations ---" << endl;
    filename = "./testfiles/test3.pcap";
    firstTime = true;
    counter = 0;

    populateBaseFrameBuffers(filename);
    testCounter++;
    cout << "....... TEST " << testCounter << endl;
    test4();
    resetEnvironment();

    filename = "./testfiles/test3.pcap";
    firstTime = true;
    counter = 0;

    populateBaseFrameBuffers(filename);
    testCounter++;
    cout << "....... TEST " << testCounter << endl;
    cout << "After reading, we add more packets, first one without payload and then one with payload" << endl;
    test4(1);
    resetEnvironment();

    cout << "--- NEW TEST SET: packet with payload spanning two FrameBuffers ---" << endl;
    filename = "./testfiles/test3.pcap";
    firstTime = true;
    counter = 0;

    populateFrameBuffersCompleteFrameBuffer(filename);
    testCounter++;
    cout << "....... TEST " << testCounter << endl;
    test5();
    resetEnvironment();

    cout << "--- NEW TEST SET: First FrameBuffer with 24 Bytes left and next packet in the second FrameBuffer ---" << endl;
    filename = "./testfiles/test3.pcap";
    firstTime = true;
    counter = 0;

    populateFrameBuffersCompleteFrameBuffer2(filename);
    testCounter++;
    cout << "....... TEST " << testCounter << endl;
    test6();
    resetEnvironment();

    cout << "--- NEW TEST SET: First FrameBuffer complete with last packet occupying 34 Bytes in first Frame Buffer"
            "and (88 - 34) Bytes in next FrameBuffer ---" << endl;
    filename = "./testfiles/test3.pcap";
    firstTime = true;
    counter = 0;

    populateFrameBuffersCompleteFrameBuffer3(filename);
    testCounter++;
    cout << "....... TEST " << testCounter << endl;
    test7();
    resetEnvironment();

    cout << "--- NEW TEST SET: First FrameBuffer complete with +28 Bytes left. "
            "Amounts of Bytes left vary from 28 to (28 + 54)."
            "Except for first loop. Packet is stored first part at the end of first FrameBuffer and second "
            "part at the beginning of second FrameBuffer ---" << endl;
    filename = "./testfiles/test3.pcap";
    testCounter++;
    cout << "....... TEST " << testCounter << endl;
    cout << "Packet spanning two FrameBuffers doesn't have TCP payload" << endl;

    int i;
    for(i = 0; i <= 54; i ++) {
        firstTime = true;
        counter = 0;

        populateFrameBuffersCompleteFrameBuffer4(filename, 28 + i, 0);
        test8(28 + i);
        resetEnvironment();
    }

    filename = "./testfiles/test3.pcap";
    testCounter++;
    cout << "....... TEST " << testCounter << endl;
    cout << "Packet spanning two FrameBuffers doesn't have TCP payload, we read data"
            << "and then we add a new TCP packet with payload" << endl;

    for(i = 0; i <= 54; i ++) {
        firstTime = true;
        counter = 0;

        populateFrameBuffersCompleteFrameBuffer4(filename, 28 + i, 0);
        test8(28 + i, 1);
        resetEnvironment();
    }

    filename = "./testfiles/test3.pcap";
    testCounter++;
    cout << "....... TEST " << testCounter << endl;
    cout << "Packet spanning two FrameBuffers has TCP payload" << endl;

    for(i = 0; i <= 54; i ++) {
        firstTime = true;
        counter = 0;

        populateFrameBuffersCompleteFrameBuffer4(filename, 28 + i, 1);
        test9(28 + i);
        resetEnvironment();
    }

    filename = "./testfiles/test3.pcap";
    testCounter++;
    cout << "....... TEST " << testCounter << endl;
    cout << "Packet spanning two FrameBuffers has TCP payload, we read data"
            << "and then we add a new TCP packet with payload" << endl;

    for(i = 0; i <= 54; i ++) {
        firstTime = true;
        counter = 0;

        populateFrameBuffersCompleteFrameBuffer4(filename, 28 + i, 1);
        test9(28 + i, 1);
        resetEnvironment();
    }

    filename = "./testfiles/test3.pcap";
    testCounter++;
    cout << "....... TEST " << testCounter << endl;
    cout << "Lat packet in first FrameBuffer in different conditions."
            << "next packet will use next FrameBuffer in some way" << endl;

    firstTime = true;
    counter = 0;
    populateFrameBuffersCompleteFrameBuffer5(filename, 0);
    test10(0);
    resetEnvironment();

    firstTime = true;
    counter = 0;
    populateFrameBuffersCompleteFrameBuffer5(filename, 28);
    test10(28);
    resetEnvironment();

    firstTime = true;
    counter = 0;
    populateFrameBuffersCompleteFrameBuffer5(filename, 30);
    test10(30);
    resetEnvironment();

    firstTime = true;
    counter = 0;
    populateFrameBuffersCompleteFrameBuffer5(filename, 90);
    test10(90);
    resetEnvironment();


    cout << "--- NEW TEST SET: Wrap around FrameBuffer linked list. ---" << endl;
    filename = "./testfiles/test3.pcap";
    testCounter++;
    cout << "....... TEST " << testCounter << endl;
    cout << "3 FrameBuffers and wrap around" << endl;


    firstTime = true;
    counter = 0;
    gSkbMaxCountFB = 3;
    populateFrameBuffersWrapAround(filename);
    test11();
    resetEnvironment();

    testCounter++;
    cout << "....... TEST " << testCounter << endl;
    cout << "Trying to work with 2 FrameBuffers" << endl;

    firstTime = true;
    counter = 0;
    gSkbMaxCountFB = 2;
    ASSERT_THROW(populateFrameBuffersWrapAround(filename), std::exception);

//    cout << "--- NEW TEST SET: skb test ---" << endl;
//    testCounter++;
//    testSkb1();

//    cout << "--- NEW TEST SET: TLS ALERT test ---" << endl;
//    tlsUnitTest::executeTLSAlertTests(testCounter);

    cout << "*********************** END TESTS FrameBuffer ***************************" << endl;
}

TEST(SKB, SKB_fast) {
    cout << "--- NEW TEST SET: skb test ---" << endl;
    testSkb1();
    resetEnvironment();

    cout << "*********************** END TESTS SKB ***************************" << endl;
}

TEST(TLS, TLSAlert_fast) {
    uint16_t testCounter = 1;
    cout << "--- NEW TEST SET: TLS ALERT test ---" << endl;
    tlsUnitTest::executeTLSAlertTests(testCounter);

    cout << "*********************** END TESTS TLSAlert ***************************" << endl;
}


TEST(STALE_CONNECTION, STALE_CONNECTION_fast) {
    uint16_t testCounter = 1;
    cout << "--- NEW TEST SET: STALE_CONNECTION test ---" << endl;
    if (!gTestsInitialized) {
        initializeTests();
    }
    connectionUnitTest::executeStaleConnectionTests(testCounter);

    cout << "*********************** END TESTS STALE_CONNECTION ***************************" << endl;
}


TEST(REFUSED_CONNECTION, REFUSED_CONNECTION_fast) {
    uint16_t testCounter = 1;
    cout << "--- NEW TEST SET: Refused connection test ---" << endl;
    if (!gTestsInitialized) {
        initializeTests();
    }
    connectionUnitTest::executeRefusedConnectionTests(testCounter);

    cout << "*********************** END TESTS REFUSED_CONNECTION ***************************" << endl;
}

TEST(TLS_CLOSE_NOTIFY, TLS_CLOSE_NOTIFY_fast) {
    uint16_t testCounter = 1;
    cout << "--- NEW TEST SET: TLS Close notify test ---" << endl;
    if (!gTestsInitialized) {
        initializeTests();
    }
    connectionUnitTest::executeTLSCloseNotifyTests(testCounter);

    cout << "*********************** END TESTS TLS_CLOSE_NOTIFY ***************************" << endl;
}


TEST(LONG_FILE_CONNECTION, MANY_CONNECTIONS_long) {
    uint16_t testCounter = 1;
    cout << "--- NEW TEST SET: 3MB-file and many connections test ---" << endl;
    if (!gTestsInitialized) {
        initializeTests();
    }
    daemonLogging->setLogLevel(DaemonLog::LOGLevelWarning);
    connectionUnitTest::executeManyConnectionsTests(testCounter);

    cout << "*********************** END TESTS LONG_FILE_CONNECTION ***************************" << endl;
}


TEST(PCAP_DUMPER, PCAP_DUMP_fast) {
    uint16_t testCounter = 1;
    cout << "--- NEW TEST SET: PCAP Dumper test ---" << endl;
    if (!gTestsInitialized) {
        initializeTests();
    }

    filename = "./testfiles/test3.pcap";
    firstTime = true;
    gSkbMaxCountFB = SKB_MAX_COUNT_FB;
    gDumpedPackets = 0;
    resetEnvironment();

    populateBaseFrameBuffers(filename);
    cout << "....... TEST " << testCounter << endl;
    TestPCAPManager pcapMgr;
    pcapMgr.setPcapFileHandleForDump("./testfiles/openoffline.pcap");
    FrameStoreHandler *fth = FrameStoreHandler::getInstance();
    fth->dump(currSkb, &pcapMgr);

    ASSERT_EQ(gDumpedPackets, (uint32_t)8);

    resetEnvironment();

    filename = "./testfiles/test3.pcap";
    testCounter++;
    cout << "....... TEST " << testCounter << endl;
    cout << "PCAP dump and wrap around FrameBuffer linked list. 3 FrameBuffers and wrap around" << endl;

    firstTime = true;
    counter = 0;
    gSkbMaxCountFB = 3;
    gDumpedPackets = 0;

    populateFrameBuffersWrapAround(filename);
    /*
     * 2nd FrameBuffer has 2,382 Bytes left.
     * msgBuf contains 2,289 packet Bytes. Then for each one we store, a total of 2,317B is added.
     * 2,317 * 451 = 1,044,967
     * 1,048,576 - 1,044,967 - 1,227 = 2,382
     * 2,382B were left in FB 2.
     * Now we complete FrameBuffer 2 and continue in FrameBuffer 3 for wrap around:
     * The next packet will leave 65Bytes
     * Then next packet occupies 65Bytes in FrameBuffer 2 and 2,552B in FrameBuffer 3.
     * 452 * 2,317 = 1,047,284
     * 1,048,576 - 1,047,284 = 1,292 -> 1,292 - 2,552 = 1,260
     * At total of 454 more msgBuf will occupy 1,260B in FrameBuffer 2 after wrapping around.
     */

    for(int i = 0; i < 454; i++) {
        storePacket(&msgBuf);
    }

    fth = FrameStoreHandler::getInstance();
    fth->dump(currSkb, &pcapMgr);

    ASSERT_EQ(gDumpedPackets, (uint32_t)911);

    resetEnvironment();

    filename = "./testfiles/test3.pcap";
    testCounter++;
    cout << "....... TEST " << testCounter << endl;
    cout << "PCAP dump and wrap around FrameBuffer linked list. Write 1 more packet. 3 FrameBuffers and wrap around" << endl;

    firstTime = true;
    counter = 0;
    gSkbMaxCountFB = 3;
    gDumpedPackets = 0;

    populateFrameBuffersWrapAround(filename);
    for(int i = 0; i < 455; i++) {
        storePacket(&msgBuf);
    }

    fth = FrameStoreHandler::getInstance();
    fth->dump(currSkb, &pcapMgr);

    ASSERT_EQ(gDumpedPackets, (uint32_t)912);

    resetEnvironment();

    filename = "./testfiles/test3.pcap";
    testCounter++;
    cout << "....... TEST " << testCounter << endl;
    cout << "PCAP dump and stop one before wrapping around" << endl;

    firstTime = true;
    counter = 0;
    gSkbMaxCountFB = 3;
    gDumpedPackets = 0;

    populateFrameBuffersWrapAround(filename);
    for(int i = 0; i < 453; i++) {
        storePacket(&msgBuf);
    }

    fth = FrameStoreHandler::getInstance();
    fth->dump(currSkb, &pcapMgr);

    ASSERT_EQ(gDumpedPackets, (uint32_t)1363);

    resetEnvironment();

    filename = "./testfiles/test3.pcap";
    testCounter++;
    cout << "....... TEST " << testCounter << endl;
    cout << "PCAP dump, wrap around and continue trough FB 3" << endl;

    firstTime = true;
    counter = 0;
    gSkbMaxCountFB = 3;
    gDumpedPackets = 0;

    populateFrameBuffersWrapAround(filename);
    for(int i = 0; i < 454; i++) {
        storePacket(&msgBuf);
    }

    /*
     * There are 1,260B in FrameBuffer 2.
     * 452 * 2,317 = 1,047,284
     * 1,048,576 - 1,047,284 = 1,292 -> 1,292 - 1,260 = 32B left in FB2
     * Next packet will take Bytes in FB 3.
     * 2,317 - 32 = 2,285
     *
     */
    for(int i = 0; i < 452; i++) {
        storePacket(&msgBuf);
    }
    storePacket(&msgBuf);


    fth = FrameStoreHandler::getInstance();
    fth->dump(currSkb, &pcapMgr);

    ASSERT_EQ(gDumpedPackets, (uint32_t)912);

    cout << "*********************** END TESTS PCAP Dumper ***************************" << endl;
}

