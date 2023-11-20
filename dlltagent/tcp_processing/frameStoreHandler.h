/*
 * FrameStoreHandler.h
 *
 *  Created on: Mar 4, 2020
 *      Author: rodolk
 */

#ifndef FRAMESTOREHANDLER_H_
#define FRAMESTOREHANDLER_H_

#include <pcap.h>

#include <mutex>

#include "skb.h"
#include "frameBuffer.h"
#include "PCAPManager.h"

/**
 * This class is a Singleton and is responsible for handle the storage of packets, received through an
 * skb's connection, in the skb's linked list of FrameBuffers.
 * It knows how to handle FrameBuffer and skb_t.
 * It is also in charge of dumping all stored packets in a pcap file through using PCAPManager.
 *
 */
class FrameStoreHandler {
public:
    static FrameStoreHandler *getInstance() {
        if (instance_ != nullptr) {
            return instance_;
        } else {
            mtx_->lock();
            if (instance_ == nullptr) {
                instance_ = new FrameStoreHandler();
            }
            mtx_->unlock();
            return instance_;
        }
    }

    /**
     * This method stores a packet in one or more FrameBuffers in the linked list of FrameBuffers belonging to currSkb.
     * The packet could occupy a few Bytes of a FrameBuffer but it also can span many FrameBuffers if it is too large. It
     * can never have a length of (currSkb->maxCountFB - 1).
     * When a packet doesn't fit completely in the available space in a FrameBuffer, it can continue in the next FrameBuffer.
     * When all FramBuffers in the linked list have bee occupied, FrameStoreHandler will continue storing like a ring that
     * doesn't include the first FrameBuffer in the linked list. The first FrameBuffer is kept intact. So, the ring continues in
     * the second FrameBuffer. A socket must have a minimum of 3 FrameBuffers.
     *
     * @param buffer    Data to be stored corresponding to the packet.
     * @param len       Length of data in the buffer.
     * @param pcaphdr   Header with metadata for that packet, this is not the packet header but pcap header.
     * @param currSkb   skb that owns this packet.
     *
     * @return true if everything worked OK, false in case the packet is greater than allowed storage.
     */
    bool storeFrame(uint8_t *buffer, uint16_t len, struct pcap_pkthdr *pcaphdr,
            skb_t *currSkb);

    /**
     * Initializes all FrameBuffer linked list variables in *currSkb
     *
     * @param currSkb       pointer to skb whose FrameBuffer linked list variables will be initialized
     * @param maxCountFB    Max number of FrameBuffer in the linked list.
     */
    void initializeFrameBuffer(skb_t *currSkb, uint16_t maxCountFB);

    /**
     * Dumps all packets in all frame buffers of currSkb to a file using the PCAPManager
     * The file name is formed by both IP addresses and both ports and the extension is pcap.
     *
     * @param currSkb       pointer to skb whose packets will be dumped to a file.
     * @param pcapDumper    The PCAPDumper that will be writing packet by packet and already knows the filename
     */
    void dump(skb_t *currSkb, PCAPManager *pcapMgr);

    /**
     * Deletes and frees all FrameBuffers for currSkb
     *
     * @param currSkb pointer to the skb whose FrameBuffers are to be freed
     */
    void deleteFrameBufferList(skb_t *currSkb);

private:
    static FrameStoreHandler *instance_;
    static std::mutex *mtx_;
    bool logsDirSet_{false};
    char logsDirectory_[100];
    uint8_t logsDirectoryLen_{0};

    FrameStoreHandler();
    virtual ~FrameStoreHandler();
    void dumpAllFrameBuffers(skb_t *currSkb, PCAPDumper *pcapDumper);
    void dumpFrameBuffer(PCAPDumper *pcapDumper, FrameBuffer *fb, struct pcap_pkthdr *&pcaphdr, uint16_t& data1Len,
            bool& contFromPrev, bool& altBufUsed, uint8_t *auxBuffer, uint8_t *&auxBufferAlt, bool doesNotContinue);
};

#endif /* FRAMESTOREHANDLER_H_ */
