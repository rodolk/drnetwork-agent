/*
 * PCAPManager.cpp
 *
 *  Created on: Mar 30, 2020
 *      Author: rodolk
 */

#include "PCAPManager.h"

#include <pcap.h>
#include <cstdint>
#include <stdlib.h>
#include <stdio.h>

PCAPManager::~PCAPManager() {
    // TODO Auto-generated destructor stub
    if (pcapFilter_ != nullptr) {
        free((void *)pcapFilter_);
    }
}


void PCAPManager::openPCAP() {
    uint32_t localnet;
    uint32_t netmask;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fcode;
//    const char *device = "eth0";
//    char *device = "lo";
    int res;


    //device = pcap_lookupdev(errbuf);
    //if (device == NULL) {
    //    log_->error("ERROR-1: open_pcap:%s\n", errbuf);
    //    exit(3);
    //}

    log_->info("DEVICE: %s\n", pcapDevice_);

    //pcapHandle_ = pcap_open_live(pcapDevice_, snaplen_, promiscSetting_, 500, errbuf);

    pcapHandle_ = pcap_create(pcapDevice_, errbuf);
    if (pcapHandle_ == NULL) {
        log_->error("ERROR-2-%s\n", errbuf);
        exit(4);
    }
    res = pcap_set_timeout(pcapHandle_, 3000);
    if (res != 0) {
        log_->error("pcap_set_timeout returned: %d\n", res);
    }

    //res = pcap_set_immediate_mode(pcapHandle_, 1);
    //res = pcap_set_buffer_size(pcapHandle_, 65000);
    res = pcap_set_promisc(pcapHandle_, promiscSetting_);
    if (res != 0) {
        log_->error("pcap_set_promisc returned: %d\n", res);
    }
    res = pcap_set_snaplen(pcapHandle_, snaplen_);
    if (res != 0) {
        log_->error("pcap_set_snaplen returned: %d\n", res);
    }

    res = pcap_activate(pcapHandle_);
    if (res != 0) {
        if (res < 0) {
            log_->error("Could not activate pcap handler, error code: %d\n", res);
        } else {
            log_->warning("pcap_activate returned an unexpected result: %d\n", res);
        }
        exit(4);
    }


    if (pcap_lookupnet(pcapDevice_, &localnet, &netmask, errbuf) < 0) {
        log_->error("ERROR getting network: %s\n", errbuf);
        //this is not critical because in K8s nodes, interfaces for pods don't have IP address
        netmask = PCAP_NETMASK_UNKNOWN;
    }

    if (pcap_compile(pcapHandle_, &fcode, pcapFilter_, 0, netmask) < 0) {
        log_->error("ERROR-4-%s\n", pcap_geterr(pcapHandle_));
        exit(6);
    }

    if (pcap_setfilter(pcapHandle_, &fcode) < 0) {
        log_->error("ERROR-5-%s\n", pcap_geterr(pcapHandle_));
        exit(7);
    }

    datalink_ = pcap_datalink(pcapHandle_);

    if (datalink_ < 0) {
        log_->error("ERROR-6-%s\n", pcap_geterr(pcapHandle_));
        exit(8);
    }

    log_->info("DATALINK: %d\n", datalink_);
}


void PCAPManager::cleanup() {
    struct pcap_stat stat;

    fflush(stdout);
    putc('\n', stdout);

    if (pcap_stats(pcapHandle_, &stat) < 0) {
        log_->info("%d packets received by filter\n", stat.ps_recv);
        log_->info("%d packets dropped by kernel\n", stat.ps_drop);
    }
}
