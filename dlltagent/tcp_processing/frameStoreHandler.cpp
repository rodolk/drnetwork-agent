/*
 * FrameStoreHandler.cpp
 *
 *  Created on: Mar 4, 2020
 *      Author: rodolk
 */

#include "frameStoreHandler.h"

#include <exception>

#include <pcap.h>
#include <arpa/inet.h>

#include "daemonLog.h"
#include "PCAPManager.h"
#include "skb.h"
#include "timeHelper.h"
#include "Configuration.h"

FrameStoreHandler *FrameStoreHandler::instance_ = nullptr;
std::mutex *FrameStoreHandler::mtx_ = new std::mutex();

FrameStoreHandler::FrameStoreHandler() {
    // TODO Auto-generated constructor stub

}

FrameStoreHandler::~FrameStoreHandler() {
    // TODO Auto-generated destructor stub
}

/**
 * It stores the data in buffer and pcap header in pcaphdr in the skb's linked list of FrameBuffers, beginning
 * in the FrameBuffer pointed to by currSkb->currFrameBuffer.
 * It invokes method currFrameBuffer->addData.
 * If all data in buffer cannot fit in currFrameBuffer it will continue storing the remaining data in the next
 * FrameBuffer in the list if there is a next one, using method FrameBuffer.addRemainingData .
 * If there are no more FrameBuffers available, there are two possibilities:
 * 1-If the number of FrameBuffers is LT currSkb->maxCountFB a new FrameBuffer is added to the linked list.
 * 2-Otherwise it sill continue in the second FrameBuffer in the linked list: currSkb->headFrameBuffer->next_
 *
 * The linked list must hold a minimum of 3 FrameBuffers.
 *
 * @caution: we cannot store packets that span more than 2 FrameBuffers (FrameBuffer::bufferSize_ * 2)
 * @caution: We assume currSkb->currFrameBuffer is never nullptr and thus we save one 'if'
 *           If currSkb->currFrameBuffer can be null, then we need to change this code to check for null
 */
bool FrameStoreHandler::storeFrame(uint8_t *buffer, uint16_t len, struct pcap_pkthdr *pcaphdr,
        skb_t *currSkb) {
    uint32_t copiedLen = currSkb->currFrameBuffer->addData(buffer, len, pcaphdr);

    if (copiedLen < len) {
        uint32_t totalCopiedLen = copiedLen;
        //TODO: check a better mechanism
//        if ((len + sizeof(uint32_t) + sizeof(struct pcap_pkthdr)) < FrameBuffer::bufferSize_ * (currSkb->maxCountFB - 1)) {
        if ((len + sizeof(uint32_t) + sizeof(struct pcap_pkthdr)) < (FrameBuffer::bufferSize_ * 2)) {
            do {
                //Are we in the last FrameBuffer in the linked list?
                if (currSkb->currFrameBuffer->next_ == nullptr) {
                    if (currSkb->countFB < currSkb->maxCountFB) {
                        currSkb->currFrameBuffer->next_ = new FrameBuffer();
                        currSkb->currFrameBuffer->next_->previous_ = currSkb->currFrameBuffer;
                        currSkb->currFrameBuffer->next_->next_ = nullptr;
                        currSkb->currFrameBuffer = currSkb->currFrameBuffer->next_;
                        currSkb->countFB++;
                    } else {
                        //The first frame buffer is left intact because there we have the connection establishment information
                        currSkb->currFrameBuffer = currSkb->headFrameBuffer->next_;
                        currSkb->currFrameBuffer->reset();
                        SET_SKB_FB_WRAP_AROUND(currSkb);
                        /*
                         * If the second FrameBuffer's offsetFirst_ > 0, that means the last packet
                         * of headFrameBuffer continues in the second FrameBuffer and we will lose it and mourn it.
                         */

                        //We cannot have (currSkb->maxCountFB == 2). We're forcing a minimum of 3 in initializeFrameBuffer
                        //If we write from the beginning of the same FB (because we have only two, then we write this packet from the beginning.
                    }
                } else {
                    currSkb->currFrameBuffer = currSkb->currFrameBuffer->next_;
                    currSkb->currFrameBuffer->reset();
                }

                //In the calls below we are assured copiedLen will always be GT 0 because we are writing to a
                //new FrameBuffer from the start.
                if (copiedLen != 0) {
                    copiedLen = currSkb->currFrameBuffer->addRemainingData(
                            buffer + totalCopiedLen, len - totalCopiedLen);
                } else {
                    //The only time we can enter here is if the first call to currFrameBuffer->addData returned 0.
                    copiedLen = currSkb->currFrameBuffer->addData(
                            buffer, len, pcaphdr);
                }
                totalCopiedLen += copiedLen;
            } while (totalCopiedLen < len);
        } else {
            std::cerr << "ERROR: trying to store too large packet: " << len << " - copied: " << totalCopiedLen << std::endl;
            return false;
        }
    }

    return true;
}

/**
 * maxCountFB can never be less than 3 because that affects wrap around. If I modify this control, I have to modify the wrap aorund code in
 * storeFrame and check rest of the code.
 *
 */
void FrameStoreHandler::initializeFrameBuffer(skb_t *currSkb, uint16_t maxCountFB) {
    if (maxCountFB <= 2) {
        std::cerr << "ERROR: An SKB cannot work with less than 3 FrameBuffers" << std::endl;
        throw std::exception();
    }
    currSkb->headFrameBuffer = new FrameBuffer();
    currSkb->currFrameBuffer = currSkb->headFrameBuffer;
    currSkb->countFB++;
    currSkb->maxCountFB = maxCountFB;
}

#define MAX_PREALLOC_BUFFER_LEN 2000

void FrameStoreHandler::dump(skb_t *currSkb, PCAPManager *pcapMgr) {
    char data[200];
    char *dataPtr;

    if (!logsDirSet_) {
        strcpy(logsDirectory_, Configuration::getInstance().logsDirectory.c_str());
        logsDirectoryLen_ = strlen(logsDirectory_);
        logsDirSet_ = true;
    }
    dataPtr = (char *)data;
    sprintf(data, "%s/%s", logsDirectory_, "dump_");
    dataPtr += (logsDirectoryLen_ + 6);
    const char *resIP = inet_ntop(AF_INET, (const void *)(currSkb->ipSrc), dataPtr, INET_ADDRSTRLEN + 1);
    if (resIP == NULL) {

    }
    dataPtr = strchr((char *)data, '\0');
    *dataPtr = '_';
    dataPtr += 1;
    resIP = inet_ntop(AF_INET, (const void *)(currSkb->ipDst), dataPtr, INET_ADDRSTRLEN + 1);
    if (resIP == NULL) {

    }
    dataPtr = strchr((char *)dataPtr, '\0');

    sprintf(dataPtr, "_%u_%u_%s.pcap", currSkb->portSrc, currSkb->portDst, getNowTimeAsString().c_str());
    PCAPDumper *pcapDumper = pcapMgr->makePCAPDumper(data);

    dumpAllFrameBuffers(currSkb, pcapDumper);

    pcapMgr->releasePCAPDumper(pcapDumper);
}

/**
 * Dumps all packets in a FrameBuffer.
 * If the last packet in the FrameBuffer continues in the next FrameBuffer, contFromPrev will be set to
 * true. It will also:
 * -Copy the data in this FrameBuffer to auxBuffer, if packet's total data fits in the preallocated static buffer.
 *  This is faster.
 * -Copy the data to a newly allocated auxBufferAlt if all data for this packet will not fit in the preallocated buffer.
 *  After dumping this packet, auxBufferAlt must be freed!
 *
 *
 * @param pcapDumper    responsible for writing packet header and data to file.
 * @param fb            FrameBuffer whose packets are written to file
 * @param pcaphdr       pcaphdr is return with the correct packet header if the last packet continues in next FrameBuffer.
 * @param dataLen       length of data already copied to buffer
 * @param contFromPrev  Set to true if last packet continues in next FrameBuffer
 * @param altBufUsed    Set to true if auxBufferAlt was allocated and used
 * @param auxBuffer
 * @param auxBufferAlt
 */
void FrameStoreHandler::dumpFrameBuffer(PCAPDumper *pcapDumper, FrameBuffer *fb, struct pcap_pkthdr *&pcaphdr, uint16_t& dataLen,
        bool& contFromPrev, bool& altBufUsed, uint8_t *auxBuffer, uint8_t *&auxBufferAlt, bool doesNotContinue) {
    uint32_t offsetNextPkt;
    uint32_t pktCount;
    uint8_t *pktData;

    if (fb->countPackets_ != 0) {
        offsetNextPkt = fb->offsetFirst_;
        pktCount = 1;
        while(pktCount < fb->countPackets_) {
            pcaphdr = (struct pcap_pkthdr *)(fb->data_ + offsetNextPkt + sizeof(uint32_t));
            pktData = (uint8_t *)(fb->data_ + offsetNextPkt + fb->kFramePktHdr_);
            pcapDumper->savePacket(pcaphdr, pktData);
            offsetNextPkt = *((uint32_t *)(fb->data_ + offsetNextPkt));
            pktCount++;
        }
        pcaphdr = (struct pcap_pkthdr *)(fb->data_ + offsetNextPkt + sizeof(uint32_t));
        pktData = (uint8_t *)(fb->data_ + offsetNextPkt + fb->kFramePktHdr_);
        dataLen = fb->bufferSize_ - (offsetNextPkt + fb->kFramePktHdr_);
        if (dataLen < pcaphdr->caplen) {
            if (!doesNotContinue) {
                contFromPrev = true;
                if (pcaphdr->caplen <= MAX_PREALLOC_BUFFER_LEN) {
                    memcpy(auxBuffer, pktData, dataLen);
                    altBufUsed = false;
                } else {
                    auxBufferAlt = (uint8_t *)malloc(pcaphdr->caplen);
                    memcpy(auxBufferAlt, pktData, dataLen);
                    altBufUsed = true;
                }
            } else {
                /*
                 * If this is the headFrameBuffer_ and there was wraparound, the last packet is lost.
                 * We need to make it different so that somebody looking at the pcap will note this case
                 * and realize there is a jump.
                 */
                struct pcap_pkthdr auxpcaphdr;
                auxpcaphdr.caplen = dataLen;
                auxpcaphdr.len = pcaphdr->len;
                auxpcaphdr.ts = {0, 0};
                pcapDumper->savePacket(&auxpcaphdr, pktData);
            }
        } else {
            contFromPrev = false;
            pcapDumper->savePacket(pcaphdr, pktData);
        }
    }
}


/**
 * Dumps all packets in all frame buffers of currSkb to a file using the PCAPDumper
 * headFrameBuffer is always saved first.
 * Then it depends on whether it wrapped around and formed a ring.
 * If it wrapped around, the next frame to save is currSkb->currFrameBuffer->next_.
 * Otherwise, it is headFrameBuffer->next_
 *
 * If there is a packet in the FrameBuffer that continues in the next FrameBuffer, contFromPrev will be set to
 * true by dumpFrameBuffer. It will also:
 * -Copy the data in this FrameBuffer to auxBuffer, if packet's total data fits in the preallocated static buffer.
 *  This is faster.
 * -Copy the data to a newly allocated auxBufferAlt if all data for this packet will not fit in the preallocated buffer.
 *  After dumping this packet, auxBufferAlt must be freed!
 *
 * Refer to dumpFrameBuffer
 *
 * @param currSkb       pointer to skb whose packets will be dumped to a file.
 * @param pcapDumper    The PCAPDumper that will be writing packet by packet and already knows the filename
 *
 * @caution this function assumes there is no packet spanning more than 2 FrameBuffers
 *
 */
void FrameStoreHandler::dumpAllFrameBuffers(skb_t *currSkb, PCAPDumper *pcapDumper) {
    uint8_t auxBuffer[MAX_PREALLOC_BUFFER_LEN];
    uint8_t *auxBufferAlt = nullptr;
    bool altBufUsed = false;
    bool contFromPrev = false; //Flag to check if we have in this FB the second half of a previous packet
    struct pcap_pkthdr *pcaphdr;
    uint16_t dataLen;
    FrameBuffer *fbLast; // Last FrameBuffer tells me the last frame buffer currently being used in the linked list, possibly a ring
    FrameBuffer *fb;

    fb = currSkb->headFrameBuffer;

    if (fb != nullptr) {
        dumpFrameBuffer(pcapDumper, fb, pcaphdr, dataLen, contFromPrev, altBufUsed, auxBuffer, auxBufferAlt,
                (IS_SKB_FB_WRAP_AROUND(currSkb)));

        //If there is another FrameBuffer after currSkb->headFrameBuffer
        if (fb->next_ != nullptr) {
            if (IS_SKB_FB_WRAP_AROUND(currSkb)) {
                fb = (currSkb->currFrameBuffer->next_ != nullptr) ?
                        currSkb->currFrameBuffer->next_ : currSkb->headFrameBuffer->next_;
                fbLast = fb;
                contFromPrev = altBufUsed = false;
                if (auxBufferAlt != nullptr) {
                    free(auxBufferAlt);
                    auxBufferAlt = nullptr;
                }
            } else {
                fb = fb->next_; //At this moment this is currSkb->headFrameBuffer->next
                fbLast = fb;
            }

            do {
                if (contFromPrev) { //This FrameBuffer has a packet continuing from previous frame buffer
                    if (!altBufUsed) {
                        memcpy(auxBuffer + dataLen, fb->data_, pcaphdr->caplen - dataLen);
                        pcapDumper->savePacket(pcaphdr, auxBuffer);
                    } else {
                        memcpy(auxBufferAlt + dataLen, fb->data_, pcaphdr->caplen - dataLen);
                        pcapDumper->savePacket(pcaphdr, auxBufferAlt);
                        altBufUsed = false;
                        free(auxBufferAlt);
                        auxBufferAlt = nullptr;
                    }
                    contFromPrev = false;
                }
                dumpFrameBuffer(pcapDumper, fb, pcaphdr, dataLen, contFromPrev, altBufUsed, auxBuffer, auxBufferAlt, false);
                fb = (fb->next_ != nullptr) ?
                        fb->next_ : currSkb->headFrameBuffer->next_;
            } while (fb != fbLast);
        }
        if (auxBufferAlt != nullptr) {
            std::cerr << "Something weird in dumpAllFrameBuffers: auxBufferAlt is not null" << std::endl;
            free(auxBufferAlt);
        }
    }
}


void FrameStoreHandler::deleteFrameBufferList(skb_t *currSkb) {
    FrameBuffer *nextFrame = currSkb->headFrameBuffer;
    FrameBuffer *delFrame;
    uint16_t i = 0;

    if (currSkb->headFrameBuffer == nullptr) return;

    while(i < currSkb->countFB) {
        delFrame = nextFrame;
        nextFrame = nextFrame->next_;
        delete delFrame;
        i++;
    }
    currSkb->headFrameBuffer = nullptr;
    currSkb->currFrameBuffer = nullptr;
    currSkb->countFB = 0;
}

