/*
 * TCPSegmentIterator.cpp
 *
 *  Created on: Apr 3, 2020
 *      Author: rodolk
 */

#include "TCPSegmentIterator.h"


TCPSegmentIterator::~TCPSegmentIterator() {
    // TODO Auto-generated destructor stub
}

/*
 * Caution: this function is called only when caplen > total len of packet whose first part is
 * in current frameBuffer
 * When we pass to the next FrameBuffer we we assume the packet continues there, always.
 */
uint32_t TCPSegmentIterator::getTCPPayloadIndexWithCheck(bool& moreDataAvailable, uint16_t dataCount) {
    uint8_t ipHdrLenW = 0;
    uint16_t remainingIPHdrLen = 0;
    //uint8_t datagramLenByte1;
    //uint8_t datagramLenByte2;
    //uint16_t datagramLen = 0;
    //uint16_t tcpMsgLen = 0;
    uint16_t tcpHdrLen = 0;
    uint16_t availableData = dataCount;
    uint32_t idx = frameBufferCurrOffset_ + sizeof(uint32_t) + sizeof(struct pcap_pkthdr);

    /*
     * Caution: we assume in a new frame, described by the packet header as captured by pcap and with length CAPLEN,
     * availableData is enough to contain all Ether, IP, and TCP headers.
     */

    if (availableData >= (ETHER_DEFAULT_HDR_LEN + 1)) {
        ipHdrLenW = framePtr_->data_[idx + ETHER_DEFAULT_HDR_LEN] & 0x0F;
        idx += (ETHER_DEFAULT_HDR_LEN + 1);
        availableData -= (ETHER_DEFAULT_HDR_LEN + 1);
    } else {
        framePtr_ = nextFrame();
        idx = ETHER_DEFAULT_HDR_LEN - availableData;
        ipHdrLenW = framePtr_->data_[idx] & 0x0F;
        idx++;
        availableData = framePtr_->offsetFirst_ - idx;
    }
    if (availableData >= POS_IP_LEN) {
        //datagramLenByte1 = framePtr_->data_[idx + POS_IP_LEN - 1];
        idx += POS_IP_LEN;
        availableData -= POS_IP_LEN;
    } else {
        framePtr_ = nextFrame();
        idx = (POS_IP_LEN - 1) - availableData;
        //datagramLenByte1 = framePtr_->data_[idx];
        idx++;
        availableData = framePtr_->offsetFirst_ - idx;
    }
    if (availableData >= 1) {
        //datagramLenByte2 = framePtr_->data_[idx];
        idx++;
        availableData -= 1;
    } else {
        framePtr_ = nextFrame();
        idx = 0;
        //datagramLenByte2 = framePtr_->data_[idx];
        idx++;
        availableData = framePtr_->offsetFirst_ - idx;
    }

    //datagramLen = (uint16_t)datagramLenByte1<<8 | (uint16_t)datagramLenByte2;
    remainingIPHdrLen = (ipHdrLenW * 4) - (POS_IP_LEN + 2);
    //tcpMsgLen = datagramLen - (ipHdrLenW * 4);

    if (availableData >= remainingIPHdrLen + POS_TCP_HDR_LEN + 1) {
        tcpHdrLen = ((framePtr_->data_[idx + remainingIPHdrLen + POS_TCP_HDR_LEN] & 0xF0) >> 4) * 4;
        idx += (remainingIPHdrLen + POS_TCP_HDR_LEN + 1);
        availableData -= (remainingIPHdrLen + POS_TCP_HDR_LEN + 1);
    } else {
        framePtr_ = nextFrame();
        idx = (remainingIPHdrLen + POS_TCP_HDR_LEN) - availableData;
        tcpHdrLen = ((framePtr_->data_[idx] & 0xF0) >> 4) * 4;
        idx++;
        availableData = framePtr_->offsetFirst_ - idx;
    }

    if (availableData >= (tcpHdrLen - (POS_TCP_HDR_LEN + 1))) {
        idx += (tcpHdrLen - (POS_TCP_HDR_LEN + 1));
        availableData -= (tcpHdrLen - (POS_TCP_HDR_LEN + 1));
    } else {
        framePtr_ = nextFrame();
        idx = (tcpHdrLen - (POS_TCP_HDR_LEN + 1)) - availableData;
        availableData = framePtr_->offsetFirst_ - idx;
    }

    /*
     * At this point, if this is a TCP msg without payload then idx isn't valid within this packet.
     * For example, just an ACK or a SYN. If he TCP segment has payload, idx will point to the first
     * Byte of TCP data.
     *
     */
    if (availableData > 0) {
        //This means there is TCP payload
        //If this is true it is because we passed to the next FrameBuffer
        if (idx < framePtr_->offsetFirst_) {
            frameBufferCurrOffset_ = 0;
            currPktNumInFrame_ = 0;
        }
        frameBufferIter_ = idx;
        frameBufferIterValid_ = true;
        moreDataAvailable = true;
    } else {
        //In this case we don't know if there is TCP Payload
        //uint16_t tcpPayloadLen = tcpMsgLen - tcpHdrLen;

        //Here we assume all headers including TCP header are not that large to go through many frameBuffers
        //Also we know that last packet is not completely in original frameBuffer. It spans two frameBuffers.
        if (idx == FrameBuffer::bufferSize_) {
            //Asume we are in the original frameBuffer
            framePtr_ = nextFrame();
            idx = 0;
            frameBufferCurrOffset_ = 0;
            frameBufferIter_ = idx;
            //(tcpPayloadLen > 0) is always true because caplen > packetLen
            frameBufferIterValid_ = true;
            moreDataAvailable = true;
            currPktNumInFrame_ = 0;
        } else {
            //We passed to the next FrameBuffer and there is no payload in the packet coming
            //from the previous one
            frameBufferCurrOffset_ = framePtr_->offsetFirst_;
            //idx is the same as offsetFirst_
            frameBufferIter_ = idx;
            frameBufferIterValid_ = false;
            moreDataAvailable = false;
            if (framePtr_->countPackets_ == 0) {
                currPktNumInFrame_ = 0;
                end_ = true;
            } else {
                currPktNumInFrame_ = 1;
            }
        }
    }
    return idx;
}



void TCPSegmentIterator::processLastCompletePacketInFrame(bool& moreDataAvailable, bool& endPerNoMorePackets) {
    uint32_t nextTCPPayloadIdx = getTCPPayloadIndex(
            frameBufferCurrOffset_ + framePtr_->kFramePktHdr_);
    if (nextTCPPayloadIdx > 0) {
        //There is data available, now pointers are set and we're done
        frameBufferIter_ = nextTCPPayloadIdx;
        frameBufferIterValid_ = true;
        moreDataAvailable = true;
    } else {
        //At this point we have processed the last packet in the FrameBuffer and there is no more data available yet.
        //We need to pass to the next FrameBuffer, if any, and check if there is a first packet there.
        //We use GET_OFFSET and the next  offset could have nothing valid, it could also be FrameBuffer::bufferSize_ if
        //the whole FrameBuffer was used

        if (isNextPacketInNextFrame(GET_OFFSET(framePtr_, frameBufferCurrOffset_))) {
            //There is a next frame with a packet. Let's leave pointers correctly
            framePtr_ = nextFrame();
            frameBufferCurrOffset_ = framePtr_->offsetFirst_;
            currPktNumInFrame_ = 1;
            nextTCPPayloadIdx = getTCPPayloadIndex(
                    frameBufferCurrOffset_ + framePtr_->kFramePktHdr_);
            if (nextTCPPayloadIdx > 0) {
                frameBufferIter_ = nextTCPPayloadIdx;
                frameBufferIterValid_ = true;
                moreDataAvailable = true;
            } else {
                frameBufferCurrOffset_ = GET_OFFSET(framePtr_, frameBufferCurrOffset_);
                frameBufferIter_ = frameBufferCurrOffset_;
                frameBufferIterValid_ = false;
                //TODO: Is this OK?
                moreDataAvailable = false;
                if (framePtr_->countPackets_ == 1) { //This is the last packet in this new FrameBuffer
                    endPerNoMorePackets = true;
                }
            }
        } else {
            //We have processed the last packet in the current FrameBuffer and there is no other packet
            //either in this FrameBuffer or in the next one if there is a next FrameBuffer (framePtr_->next_)
            //TODO: check last nextOffset points to somewhere within the FrameBuffer
            //TODO: how do we continue with frameBufferIter_ when frameBufferIterValid_ was false?
            frameBufferCurrOffset_ = GET_OFFSET(framePtr_, frameBufferCurrOffset_);
            frameBufferIter_ = frameBufferCurrOffset_;
            frameBufferIterValid_ = false;
            moreDataAvailable = false;
            endPerNoMorePackets = true;
        }
    }
}



/**
 * We always return a pointer to the next data ready to read within a packet within a FrameBuffer only if there is data
 * available. We also return the length of that data chunk to read in ioLen. ioLen can be the length of the whole data chunk
 * in the packet or the requested length if this is smaller than the total chunk length.
 * If there is additional data available to read in this chunk or in other packet in this FrameBuffer or a following FrameBuffer,
 * we also leave:
 * -moreDataAvailable is true
 * -frameBufferIterValid_ is true
 * -frameBufferIter_ points to the first byte to read and not yet read
 *
 * If there is no data ready to read, this method returns nullptr, and ioLen will be 0 (zero).
 * The following attributes will be set:
 * -moreDataAvailable is false
 * -frameBufferIterValid_ is false
 * -frameBufferIter_ points to the offset of the next packet to be stored (not yet existing). This is t he position of
 *  the next offset corresponding to the next packet.
 *
 * currPktNumInFrame_ and framePtr_ will be set accordingly.
 * So, ioLen will tell if data was read and the pointer returned points to the beginning of that data chunk. moreDataAvailable
 * tells that there is additional data ready to be read.
 *
 * TODO: CHECK AND FIX for wrap around!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * @param ioLen       this is an input/output parameter. It receives the requested length and returns
 *                  the read length.
 * @param moreDataAvailable this is an output parameter that tells the caller if there is more data
 *                          available to read.
 * @return pointer to the beginning of the data chunk read
 *
 */
const uint8_t *TCPSegmentIterator::getTCPSegmentData(uint16_t &ioLen, bool &moreDataAvailable) {
    uint16_t requestedLen = ioLen;
    uint16_t availableLen = 0;
    const uint8_t *dataPtr = nullptr;

    moreDataAvailable = false;

    if (frameBufferIterValid_) {
        /*
         * There is data to read
         * We could be at:
         *      1-frameBuffer beginning in the following part of a partial frame
         *              frameBufferCurrOffset_==0 && framePtr_->offsetFirst_ > 0
         *      2-frameBuffer beginning at the frame start
         *              frameBufferCurrOffset_==0 && framePtr_->offsetFirst_ == 0
         *      3-Middle frame
         *              frameBufferCurrOffset_>0
         *              There is a complete frame
         *      4-Last frame
         *              frameBufferCurrOffset_>=0
         *              Complete or partial frame
         *
         */

        uint32_t nextOffset;

        //Since frameBufferIterValid_, (frameBufferIter_ < nextOffset) is always true
        dataPtr = framePtr_->data_ + frameBufferIter_;

        if (frameBufferCurrOffset_ > 0 || framePtr_->offsetFirst_ == 0) {
            nextOffset = GET_OFFSET(framePtr_, frameBufferCurrOffset_);
        } else {
            nextOffset = framePtr_->offsetFirst_;
        }
        //Get the length of data available to read within this packet
        availableLen = nextOffset - frameBufferIter_;
        if (requestedLen < availableLen) {
            ioLen = requestedLen;
            frameBufferIter_ += ioLen;
            frameBufferIterValid_ = true;
            moreDataAvailable = true; //There is more TCP payload data in this packet in this FrameBuffer
            return dataPtr;
        } else {
            ioLen = availableLen;
            frameBufferIter_ = nextOffset;
            frameBufferIterValid_ = false;
            frameBufferCurrOffset_ = nextOffset;
            if (currPktNumInFrame_ == framePtr_->countPackets_) {
                if (doesCurrPacketContinueInNextFrame(frameBufferCurrOffset_)) {
                    //There is a next frame with a continuation of current packet's payload. Let's leave pointers correctly
                    framePtr_ = nextFrame();
                    frameBufferIter_ = 0;
                    frameBufferIterValid_ = true;
                    moreDataAvailable = true;
                    currPktNumInFrame_ = 0;
                    frameBufferCurrOffset_ = 0;
                    return dataPtr;
                } else if (isNextPacketInNextFrame(frameBufferCurrOffset_)) {
                    //There is a next frame with a packet. Let's leave pointers correctly
                    framePtr_ = nextFrame();
                    frameBufferCurrOffset_ = 0; // framePtr_->offsetFirst_ is 0, otherwise we'd have a continuation.
                    currPktNumInFrame_ = 0;
                    //Then it needs to set pointers correctly in next section because now, in the next FrameBuffer,
                    //currPktNumInFrame_ < framePtr_->countPackets_
                }
            }
        }
    } else {
        //dataPtr remains nullptr because we have no data to read immediately
        //Let's check if there are more packets and if they have data available
        ioLen = 0; //availableLen is zero
        if (currPktNumInFrame_ == framePtr_->countPackets_) {
            if (isNextPacketInNextFrame(frameBufferCurrOffset_)) {
                //There is a next frame with a packet. Let's leave pointers correctly
                framePtr_ = nextFrame();
                frameBufferCurrOffset_ = framePtr_->offsetFirst_;
                currPktNumInFrame_ = 0;
            } else {
                return nullptr;
            }
        } else {
            //There are more packets in the FrameBuffer!!!
            //frameBufferCurrOffset_ points to offset of next packet
            //This is valid also when currPktNumInFrame_ is zero
        }
    }
    //At this point frameBufferCurrOffset_ is equal to nextOffset
    //Leave pointers in the next Byte of data available to read or at the very end of last packet if no data available

    if (currPktNumInFrame_ < framePtr_->countPackets_) { //TODO: write code for else
        moreDataAvailable = false;
        currPktNumInFrame_++;

        advancePointersToNextByteOfData(moreDataAvailable);
    }

    return dataPtr;
}

/**
 * This function updates the pointers looking for the first Byte of data to process in next call
 *
 *
 * @Caution: frameBufferCurrOffset_ must be pointing to the next offset before calling this function
 *           It cannot point to the offset of the packet that was already processed.
 *
 */
void TCPSegmentIterator::advancePointersToNextByteOfData(bool& moreDataAvailable) {
    end_ = false;
    while(!moreDataAvailable && !end_) {
        //We progress through the next packets until we find data or reach the the last packet in the FrameBuffer.
        while(!moreDataAvailable && currPktNumInFrame_ < framePtr_->countPackets_) {
            uint32_t nextTCPPayloadIdx = getTCPPayloadIndex(
                    frameBufferCurrOffset_ + sizeof(uint32_t) + sizeof(struct pcap_pkthdr));
            if (nextTCPPayloadIdx > 0) {
                frameBufferIter_ = nextTCPPayloadIdx;
                frameBufferIterValid_ = true;
                moreDataAvailable = true;
            } else {
                frameBufferCurrOffset_ = GET_OFFSET(framePtr_, frameBufferCurrOffset_);
                frameBufferIter_ = frameBufferCurrOffset_;
                frameBufferIterValid_ = false;
                currPktNumInFrame_++;
            }
        }

        //If we are in the last packet in the current frame
        if (!moreDataAvailable) {
            struct pcap_pkthdr *pHdr =  (struct pcap_pkthdr *)(framePtr_->data_ + frameBufferCurrOffset_ + sizeof(uint32_t));
            uint32_t leftSpaceLen = FrameBuffer::bufferSize_ -
                    (frameBufferCurrOffset_ + sizeof(uint32_t) + sizeof(struct pcap_pkthdr));
            if (pHdr->caplen > leftSpaceLen) {
                //Partial packet
                getTCPPayloadIndexWithCheck(moreDataAvailable, leftSpaceLen);
            } else {
                processLastCompletePacketInFrame(moreDataAvailable, end_);
            }
            //At this point, if it was necessary to move to next frameBuffer, we did it
        }
    }
}









