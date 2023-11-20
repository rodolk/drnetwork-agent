/*
 * TCPSegmentIterator.h
 *
 *  Created on: Apr 3, 2020
 *      Author: rodolk
 */

#ifndef TCPSEGMENTITERATOR_H_
#define TCPSEGMENTITERATOR_H_

#include <arpa/inet.h>
#include <pcap.h>

#include <cstdint>

#include "frameBuffer.h"
#include "skb.h"


#define GET_OFFSET(frameB, offset) *((uint32_t *)&((frameB)->data_[offset]))
#define ETHER_DEFAULT_HDR_LEN 14
#define POS_IP_LEN 2
#define POS_TCP_HDR_LEN 12

class TCPSegmentIterator {
public:
    TCPSegmentIterator(skb_t *skb) : skb_(skb) {}
    virtual ~TCPSegmentIterator();

    //TODO: Review and fix this. Assumes this function is called as soon as the first TCP data arrives - BE CAREFUL!!!
    uint8_t getFirstPayloadOctet() {
        framePtr_ = skb_->headFrameBuffer;
        frameBufferIter_ = skb_->firstTCPPayloadByte;
        frameBufferCurrOffset_ = framePtr_->offsetLast_;
        currPktNumInFrame_ = framePtr_->countPackets_;
        frameBufferIterValid_ = true;
        return skb_->headFrameBuffer->data_[frameBufferIter_++];
    }
    void initialize() {
        framePtr_ = skb_->headFrameBuffer;
        frameBufferIter_ = 0;
        frameBufferCurrOffset_ = framePtr_->offsetFirst_;
        currPktNumInFrame_ = 0;
        frameBufferIterValid_ = false;
    }

    uint8_t getNextPayloadOctet() {
        //TODO: Fix this - It's done for only one FrameBuffer - BE CAREFUL AND REMEMBER!!!!
        return framePtr_->data_[frameBufferIter_++];
    }

    void jumpPayloadOctets(uint16_t value) {
        //TODO: Fix this - It's done for only one FrameBuffer - BE CAREFUL AND REMEMBER!!!!
        frameBufferIter_ += value;
    }

    const uint8_t *getTCPSegmentData(uint16_t &len, bool &moreDataAvailable);

    uint32_t getOffsetLastSegment() {
        return skb_->currFrameBuffer->offsetLast_ + sizeof(uint32_t) + sizeof(struct pcap_pkthdr);
    }

private:
    FrameBuffer *framePtr_{nullptr};
    uint32_t frameBufferIter_{0};
    bool frameBufferIterValid_{false};
    uint32_t frameBufferCurrOffset_{0};
    uint32_t currPktNumInFrame_{0};
    skb_t *skb_;
    bool end_{false};

    uint32_t getTCPPayloadIndex(uint32_t idx) const {
        uint8_t hwHdrLen = ETHER_DEFAULT_HDR_LEN;
        uint8_t ipHdrLenW = framePtr_->data_[idx + ETHER_DEFAULT_HDR_LEN] & 0x0F;
        uint16_t datagramLen = ntohs(*((uint16_t *)&(framePtr_->data_[idx + 16])));
        uint32_t tcpIdx =  idx + hwHdrLen + (ipHdrLenW * 4);
        uint16_t tcpMsgLen = datagramLen - (ipHdrLenW * 4);
        uint16_t tcpHdrLen = ((framePtr_->data_[tcpIdx + 12] & 0xF0) >> 4) * 4;
        if (tcpMsgLen > tcpHdrLen) {
            return tcpIdx + tcpHdrLen;
        } else {
            return 0;
        }
    }
    /**
     * This method receives an offset for an existing packet that must be the last packet in the frame.
     * Then it checks if there no more space for an additional packet in this FrameBuffer and if there
     * is a packet in the next FrameBuffer.
     * It returns the result.
     * If the packet is not the last one in the frame this function should return false
     *
     * TODO: This doesn't consider we have a circular linked list. So the next FrameBuffer can hold an actually old packet that is not the continuation.
     * TODO: Need to fix this
     *
     * @param offset    Offset of the current packet
     * @return true     If the packets continue in the next FrameBuffer
     */
    bool isNextPacketInNextFrame(uint32_t offset) {
        return ((offset + framePtr_->kFramePktHdr_ + 1) > FrameBuffer::bufferSize_ &&
                skb_->currFrameBuffer != framePtr_ &&
                ((framePtr_->next_ && framePtr_->next_->countPackets_ > 0) ||
                        (framePtr_->next_ == nullptr &&
                                IS_SKB_FB_WRAP_AROUND(skb_) &&
                                skb_->headFrameBuffer->next_->countPackets_ > 0)));
    }

    bool doesCurrPacketContinueInNextFrame(uint32_t offset) {
        return ((offset + framePtr_->kFramePktHdr_ + 1) > FrameBuffer::bufferSize_ &&
                skb_->currFrameBuffer != framePtr_ &&
                ((framePtr_->next_ && framePtr_->next_->offsetFirst_ > 0) ||
                        (framePtr_->next_ == nullptr &&
                                IS_SKB_FB_WRAP_AROUND(skb_) &&
                                skb_->headFrameBuffer->next_->offsetFirst_ > 0)));
    }

    void advancePointersToNextByteOfData(bool& moreDataAvailable);
    uint32_t getTCPPayloadIndexWithCheck(bool& moreDataAvailable, uint16_t dataCount);
    void processLastCompletePacketInFrame(bool& moreDataAvailable, bool& endPerNoMorePackets);

    FrameBuffer *nextFrame() {
        if (framePtr_->next_ != nullptr) {
            return framePtr_->next_;
        } else {
            return skb_->headFrameBuffer->next_;
        }
    }

//We assume if firstTCPPayload, then we are in the first frameBuffer and copiedLen is eq len
//        currSkb->firstTCPPayloadByte = currSkb->currFrameBuffer->offsetLast_ + sizeof(uint32_t) +
//                sizeof(struct pcap_pkthdr) + firstTCPPayloadByte;

    friend class UnitTestChecker;
};

#endif /* TCPSEGMENTITERATOR_H_ */
