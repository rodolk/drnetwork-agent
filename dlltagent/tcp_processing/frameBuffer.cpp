/*
 * FrameBuffer.cpp
 *
 *  Created on: Mar 3, 2020
 *      Author: rodolk
 */

#include "frameBuffer.h"

#include <string.h>

size_t FrameBuffer::bufferSize_ = BUFFER_SIZE;
uint16_t FrameBuffer::increment_ = INCREMENT_DEFAULT;
size_t FrameBuffer::total_ = 0;
int FrameBuffer::countFrameBufferNew = 0;
int FrameBuffer::countFrameBufferDelete = 0;

bool FrameBuffer::initialized_ = false;
objmem_manager::MemoryManager<FrameBuffer, FrameBuffer::FRAME_BUFFER_STR> *FrameBuffer::mMgrFrameBuffer_ = nullptr;


void FrameBuffer::addExactData(uint8_t *data, size_t size, struct pcap_pkthdr *pcaphdr) {
    offsetLast_ = offsetNext_;
    *((uint32_t *)&data_[offsetNext_]) = offsetNext_ + size + kFramePktHdr_;
    offsetNext_ += sizeof(uint32_t);
    memcpy(&data_[offsetNext_], pcaphdr, sizeof(struct pcap_pkthdr));
    offsetNext_ += sizeof(struct pcap_pkthdr);
    memcpy(&data_[offsetNext_], data, size);
    offsetNext_ += size;
    //The packet is counted where it begins, not where it ends.
    countPackets_++;
}

uint32_t FrameBuffer::addData(uint8_t *data, size_t size, struct pcap_pkthdr *pcaphdr) {
    uint32_t sizeToCopy = 0;
    if ((offsetNext_ + size + kFramePktHdr_) < (bufferSize_ + 1)) {
        sizeToCopy = size;
        addExactData(data, sizeToCopy, pcaphdr);
    } else if ((offsetNext_ + kFramePktHdr_ + 1) < (bufferSize_ + 1)) {
        sizeToCopy = bufferSize_ - offsetNext_ - kFramePktHdr_;
        addExactData(data, sizeToCopy, pcaphdr);
    }
    return sizeToCopy;
}

/*
 * We are not incrementing countPackets_ here because this packet is counted for the previous FB
 */
uint32_t FrameBuffer::addRemainingData(uint8_t *data, size_t size) {
    uint32_t sizeToCopy = 0;
    if (size < bufferSize_) {
        sizeToCopy = size;
        memcpy(data_, data, sizeToCopy);
    } else {
        sizeToCopy = bufferSize_;
        memcpy(data_, data, sizeToCopy);
    }
    offsetNext_ += sizeToCopy;
    offsetFirst_ = offsetNext_;
    offsetLast_ = 0;
    return sizeToCopy;
}



