/*
 * PCAPDumper.cpp
 *
 *  Created on: Mar 30, 2020
 *      Author: rodolk
 */

#include "PCAPDumper.h"

PCAPDumper::~PCAPDumper() {
    // TODO Auto-generated destructor stub
    if (dumpfile_ != nullptr) {
        pcap_dump_close(dumpfile_);
    }
}

void PCAPDumper::savePacket(const struct pcap_pkthdr *pkthdr, const uint8_t *pkt) {
    if (dumpfile_ != nullptr) {
        pcap_dump((unsigned char *)dumpfile_, pkthdr, pkt);
    }
}
