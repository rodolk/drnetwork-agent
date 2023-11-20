/*
 * FrameBuffer.h
 *
 *  Created on: Mar 3, 2020
 *      Author: rodolk
 */

#ifndef FRAMEBUFFER_H_
#define FRAMEBUFFER_H_

#include <pcap.h>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <mutex>
#include <thread>
#include <chrono>

#include <memoryManager.h>
#include "applicationLog.h"

/*
 * In unit test we are using
 * BUFFER_SIZE = (1024 * 1024)
 * We need to keep that size for UT for now.
 * TODO: Fix unit test to be able to deal with a variable BUFFER_SIZE
 *
 */
#ifndef UNIT_TEST

#define BUFFER_SIZE (512 * 1024)

#else

#define BUFFER_SIZE (1024 * 1024)

#endif

#define INCREMENT_DEFAULT 40

/**
 * This class is used to store packets' data. Also any kind of data can be stored.
 * Every different piece of data, like a packet, that is stored, will have an offset from the beginning.
 * Any different piece of data can be uniquely identified.
 * Data is stored in the buffer data_ of size BUFFER_SIZE.
 * countPackets_ indicates how many unique pieces of data, like packets, have been stored.
 * Data is added with addData and addRemainingData.
 * static method initialize must be called before using FrameBuffer.
 *
 */
class FrameBuffer {
public:
    class AllocException : public std::exception {
    public:
        AllocException(std::string exceptionMsg = "") {
            std::stringstream sstr;
            sstr << "Could not create new FrameBuffer." << std::endl << exceptionMsg << std::endl;
            exceptionMsg_ = sstr.str();
        }

        std::string getExceptionMsg() {return exceptionMsg_;}

    protected:
        std::string exceptionMsg_;
    };

    /**
     * This method has to be called at the beginning of an application before using FrameBuffer.
     * After calling shutdown, this function must be called if FrameBuffer is to be used.
     *
     * @param count number of instances to be preallocated
     */
    static void initialize(uint32_t count) {
        try {
            mMgrFrameBuffer_ = new objmem_manager::MemoryManager<FrameBuffer, FRAME_BUFFER_STR>(count, count, 1);
            initialized_ = true;
        } catch (objmem_manager::MemoryManager<FrameBuffer, FRAME_BUFFER_STR>::MemoryMgrException& excep) {
            std::cerr << "Could not create MemoryManager<FrameBuffer>." << std::endl;
            throw AllocException(excep.what());
        }
    }

    /**
     * This function is called to completely return all memory resources used for FrameBuffer.
     * After calling this function, FrameBuffers become unusable.
     *
     */
    static void shutdown() {
        if (mMgrFrameBuffer_) delete mMgrFrameBuffer_;
        mMgrFrameBuffer_ = nullptr;
    }

    /**
     * Operator new uses MemoryManager to allocate a new FrameBuffer
     * Internal counter countFrameBufferNew can be used to detect any memory leak.
     *
     * @param size this is the size of a FrameBuffer object.
     */
    void *operator new(size_t size) {
        try {
            FrameBuffer *fb = mMgrFrameBuffer_->createInstance();
            countFrameBufferNew++; //Caution, there is race condition here if there are many threads processing incoming messages
            if (countFrameBufferNew % 100 == 0) {
                ApplicationLog::getLog().debug("New FrameBuffers: %d\n", countFrameBufferNew);
            }
            return fb;
        } catch (objmem_manager::MemoryManager<FrameBuffer, FRAME_BUFFER_STR>::MemoryMgrException& excep) {
            throw AllocException(excep.getExceptionMsg());
        }
    }

    /**
     * Operator delete returns a FrameBuffer object that is being deleted to the MemoryManager
     * Internal counter countFrameBufferDelete can be used to detect a memory leak.
     *
     * @param p pointer to the object to be deleted
     */
    void operator delete(void *p) {
        FrameBuffer *fb = (FrameBuffer *)p;
        countFrameBufferDelete++; //Caution, there is race condition here
        if (countFrameBufferDelete % 100 == 0) {
            ApplicationLog::getLog().debug("Delete FrameBuffers: %d\n", countFrameBufferDelete);
        }
        mMgrFrameBuffer_->returnInstance(fb);
    }

    /**
     * Add data in buffer data_ in the FrameBuffer. This is a complete pcap packet from its beginning.
     * The packet data is stored along with the corresponding metadata, including pcap packet header.
     * If there is no space for the complete packet data + pcap packet header + sizeof(uint32_t) (for the size of
     * all data stored + metadata) we check that there is at least enough space for (the size of stored data (uint32_t) +
     * pcap packet header + 1 Byte of the packet data). If there is not space for that minimum, we store nothing in this
     * FrameBuffer and return 0.
     *
     * @param data      Buffer with data of the packet to store
     * @param size      Size of data to store pointed by data. It doesn't include pcap packet header size (pcaphdr).
     * @param pcaphdr   pointer to the pcap packet header to store
     * @return          Amount of copied data
     */
    uint32_t addData(uint8_t *data, size_t size, struct pcap_pkthdr *pcaphdr);

    /**
     * This function adds data from the rest of a packet that didn't completely fit in the previous FrameBuffer,
     * to a complete new buffer so we have the whole bufferSize_ available.
     * This function never writes the metadata for this packet because it has ALWAYS been written in the previous
     * FrameBuffer.
     *
     * @param data  Pointer to the data to store in the FrameBuffer
     * @param size  Length of the data to store
     * @return Amount of data copied to FrameBuffer
     */
    uint32_t addRemainingData(uint8_t *data, size_t size);

    /**
     * Set all values as for a brand new FrameBuffer
     */
    void reset() {
        offsetFirst_ = 0;
        offsetNext_ = 0;
        offsetLast_ = 0;
        total_ = 0;
        countPackets_ = 0;
    }


private:
    static size_t bufferSize_;
    //How many FrameBuffers are created when system needs to create more
    static uint16_t increment_;
    //Total amount of created FrameBuffers
    static size_t total_;
    static bool initialized_;
    //static FrameBuffer *headAvailable_;
    //static FrameBuffer *headUsed_;
    //static std::mutex queueMutex_;
    static int countFrameBufferNew;
    static int countFrameBufferDelete;
    static constexpr const char FRAME_BUFFER_STR[] = "FrameBuffer";
    static objmem_manager::MemoryManager<FrameBuffer, FRAME_BUFFER_STR> *mMgrFrameBuffer_;
    const uint16_t kFramePktHdr_ = sizeof(uint32_t) + sizeof(struct pcap_pkthdr);
    //Offset of first packet beginning in this FrameBuffer
    uint32_t offsetFirst_{0};
    //Offset of the next packet to store in this FrameBuffer.
    //Also used for determining total count of Bytes in this FrameBuffer.
    uint32_t offsetNext_{0};
    //Offset of last packet (complete or not) stored in this FrameBuffer
    uint32_t offsetLast_{0};
    //Count of packets in this FrameBuffer
    uint32_t countPackets_{0};
    uint8_t data_[BUFFER_SIZE];
    FrameBuffer *next_;
    FrameBuffer *previous_;

    void addExactData(uint8_t *data, size_t size, struct pcap_pkthdr *pcaphdr);

    friend class FrameStoreHandler;
    friend class TCPSegmentIterator;
    friend class UnitTestChecker;
};

#endif /* FRAMEBUFFER_H_ */
