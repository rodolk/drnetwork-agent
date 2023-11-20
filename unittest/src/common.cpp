/*
 * common.cpp
 *
 *  Created on: Jul 6, 2021
 *      Author: rodolk
 */

#include <cstdint>
#include <iostream>
#include <gtest/gtest.h>
#include <arpa/inet.h>

//#include <unistd.h>

#include "skb.h"
#include "frameStoreHandler.h"
#include "frameBuffer.h"

#include "common.h"

uint16_t gSkbMaxCountFB = SKB_MAX_COUNT_FB;

bool firstTime = true;

skb_t *storePacket(msg_buffer_t *msgBuf) {
    uint8_t hwHdrLen = ETHER_DEFAULT_HDR_LEN;
    uint8_t ipHdrLenW;
    //uint16_t datagramLen;
    uint16_t tcpIdx;
    skb_t auxSkb;
    skb_t *processedSkb;
    FrameStoreHandler *frameStoreHandler = FrameStoreHandler::getInstance();

    //cout << "-------storing packet: " << counter++ << endl;

    ipHdrLenW = msgBuf->msg[14] & 0x0F;
    //datagramLen = ntohs(*((uint16_t *)&msgBuf->msg[16]));

    tcpIdx = hwHdrLen + (ipHdrLenW * 4);

    auxSkb.portSrc = ntohs(*((uint16_t *)&msgBuf->msg[tcpIdx]));
    auxSkb.portDst = ntohs(*((uint16_t *)&msgBuf->msg[tcpIdx + 2]));
    memcpy(auxSkb.ipSrc, &msgBuf->msg[26], 4);
    memcpy(auxSkb.ipDst, &msgBuf->msg[30], 4);

    if (firstTime) {
        processedSkb = get_new_skb();

        memcpy((void *)processedSkb, (void *)&auxSkb, SIZE_OF_IP_PORT);

        processedSkb->cStatus = SYN;
        //RESET_SKB_VALID_CNT(processedSkb);
        //RESET_SKB_STATE_VALID(processedSkb);
        RESET_STATE(processedSkb);
        processedSkb->syncRetries = 0;
        processedSkb->initialTime = msgBuf->hdr.ts;
        processedSkb->origPortSrc = processedSkb->portSrc;
        processedSkb->origPortDst = processedSkb->portDst;
        memcpy(processedSkb->origIpSrc, processedSkb->ipSrc, IPV4_ADDR_LEN);

        addNewSkb(processedSkb);
        frameStoreHandler->initializeFrameBuffer(processedSkb, gSkbMaxCountFB);
        firstTime = false;
    } else {
        processedSkb = skbLookup(&auxSkb);
    }

    frameStoreHandler->storeFrame(msgBuf->msg, msgBuf->len, &(msgBuf->hdr), processedSkb);

    return processedSkb;
}


