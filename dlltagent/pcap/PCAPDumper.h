/*
 * PCAPDumper.h
 *
 *  Created on: Mar 30, 2020
 *      Author: rodolk
 */

#ifndef PCAPDUMPER_H_
#define PCAPDUMPER_H_

#include <pcap.h>

#include <string>
#include <iostream>

class PCAPManager;

class PCAPDumper {
public:
    /**
     * Saves the passed packet to a file
     *
     * @param pkthdr ptr to pcap packet header
     * @param pkt    ptr to packet data
     */
    virtual void savePacket(const struct pcap_pkthdr *pkthdr, const uint8_t *pkt);

protected:
    pcap_dumper_t *dumpfile_{nullptr};
    std::string filename_;

    /**
     * It opens the pcap dump file. pcapHandle is only needed by pcap_dump_open
     * to create the file header.
     * dumpfile_ is closed in the destructor if it is !nullptr
     *
     * @param pcapHandle
     *
     * @return true if init was successful. Otherwise, false.
     */
    virtual bool init(pcap_t *pcapHandle) {
        dumpfile_ = pcap_dump_open(pcapHandle, filename_.c_str());
        if(dumpfile_ == nullptr) {
            std::cerr << "Error opening output file: " << pcap_geterr(pcapHandle) << std::endl;
            return false;
        }
        return true;
    }

    PCAPDumper(const char *filename) : filename_(filename) {}

    virtual ~PCAPDumper();

    friend class PCAPManager;
};

#endif /* PCAPDUMPER_H_ */
