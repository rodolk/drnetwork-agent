/*
 * processConnectEBPF.cpp
 *
 *  Created on: Dec 17, 2021
 *      Author: rodolk
 */

#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/resource.h>

#include "ebpf_proc_common.h"
#include "daemon_log.h"

#define MAX_TCP_CONN_ENTRIES 256

static struct bpf_object *gBpfObj;
static struct bpf_program *gProgProbe;
static struct bpf_program *gProgRetProbe;
static struct bpf_link *gLinkProgProbe;
static struct bpf_link *gLinkProgRetProbe;
static int mapIndexfd;
static int mapTCPConnfd;
static struct tcpconn__ProcessConnEBPF tcpconn;
static struct rlimit lim = {
    .rlim_cur = RLIM_INFINITY,
    .rlim_max = RLIM_INFINITY,
};

#define FALSE 0
#define TRUE 1

//ProcessConnEBPF
int initialize_ProcessConnEBPF(const char *ebpfObjPath, const char * logDirectory, const char *logFilename, unsigned int logLevel);
int cleanAll_ProcessConnEBPF(void);
int retrieveNextTCPConnection(struct tcpconn__ProcessConnEBPF *);


int initialize_ProcessConnEBPF(const char *ebpfObjPath, const char * logDirectory, const char *logFilename, unsigned int logLevel) {
    char filename[256];
    snprintf(filename, sizeof(filename), "%s/processConnEBPF_kern.o", ebpfObjPath);
    initializeWithFile("errorEBPF.log", logDirectory, logFilename, logLevel);

    loginfo("Initializing EBPF\n");

    setrlimit(RLIMIT_MEMLOCK, &lim);

    gBpfObj = bpf_object__open(filename);
    if (libbpf_get_error(gBpfObj)) {
        logerror("ERROR: opening BPF object file failed\n");
        return 0;
    }

    gProgProbe = bpf_object__find_program_by_title(gBpfObj, "kprobe/tcp_v4_connect");
    if (!gProgProbe) {
        logerror("ERROR: finding a gProgProbe in gBpfObj file failed\n");
        goto err;
    }
    bpf_program__set_type(gProgProbe, BPF_PROG_TYPE_KPROBE);

    gProgRetProbe = bpf_object__find_program_by_title(gBpfObj, "kretprobe/tcp_v4_connect");
    if (!gProgRetProbe) {
        logerror("ERROR: finding a gProgRetProbe in gBpfObj file failed\n");
        goto err;
    }
    bpf_program__set_type(gProgRetProbe, BPF_PROG_TYPE_KPROBE);

    /* load BPF program */
    if (bpf_object__load(gBpfObj)) {
        logerror("ERROR: loading BPF object file failed\n");
        goto err;
    }

    gLinkProgProbe = bpf_program__attach_kprobe(gProgProbe, FALSE, "tcp_v4_connect");
/*    link = bpf_program__attach(prog); */
    if (libbpf_get_error(gLinkProgProbe)) {
        logerror("ERROR: attaching BPF program to kprobe/tcp_v4_connect\n");
        goto err;
    }

    gLinkProgRetProbe = bpf_program__attach_kprobe(gProgRetProbe, TRUE, "tcp_v4_connect");
/*    link = bpf_program__attach(prog); */
    if (libbpf_get_error(gLinkProgRetProbe)) {
        logerror("ERROR: attaching BPF program, gLinkProgRetProbe, to kretprobe/tcp_v4_connect\n");
        goto err1;
    }

    mapIndexfd = bpf_object__find_map_fd_by_name(gBpfObj, "my_map_index");
    if (mapIndexfd < 0) {
        logerror("Error-1, get map fd from bpf gBpfObj failed\n");
        goto err2;
    }

    mapTCPConnfd = bpf_object__find_map_fd_by_name(gBpfObj, "tcpconn_map");
    if (mapTCPConnfd < 0) {
        logerror("Error-2, get map fd from bpf gBpfObj failed\n");
        goto err2;
    }

    return 0;

    err2:
        bpf_link__destroy(gLinkProgRetProbe);
    err1:
        bpf_link__destroy(gLinkProgProbe);
    err:

        bpf_object__close(gBpfObj);
        return 1;
}

//static uint32_t counter = 0;
/**
 * This process communicates with our EBPF module to get information about a new connection
 *
 * @caution: this process is not thread-safe
 * @param tcp_conn_client
 * @return  0: No new connection and no error
 *          1: A new connection and no error
 *          negative: Error
 */
int retrieveNextTCPConnection(struct tcpconn__ProcessConnEBPF *tcp_conn_client) {
    static uint32_t keyindex = 0;
    static uint8_t idxvalue = 0;
    static uint8_t prev_idxvalue = 0; //Since it's 1 Byte we assure wrap around after 255
    uint32_t prev_idxvalue2;

    int res = bpf_map_lookup_elem(mapIndexfd, &keyindex, &idxvalue);
    if (res == 0) {
        logdebug("READ IDXVALUE: %u\n", idxvalue);
        logdebug("PREVIDXVALUE: %u\n", prev_idxvalue);
        if (idxvalue != prev_idxvalue) {
            prev_idxvalue++;
            prev_idxvalue2 = prev_idxvalue;
            res = bpf_map_lookup_elem(mapTCPConnfd, &prev_idxvalue2, &tcpconn);
            if (res == 0) {
                logdebug("NEW CONNECTION:\n");
                logdebug("TGID: %d, PID: %d, COMM: %s, PPID: %d, UID: %u\n", tcpconn.tgid, tcpconn.pid, tcpconn.comm, tcpconn.ppid, tcpconn.uid);
                uint8_t *ipfrom = (uint8_t *)&tcpconn.saddr;
                uint8_t *ipto = (uint8_t *)&tcpconn.daddr;
                //lport is already in host byte order. We need to convert dport though.
                logdebug("%u.%u.%u.%u:%u -> %u.%u.%u.%u:%u\n", ipfrom[0], ipfrom[1], ipfrom[2], ipfrom[3], tcpconn.lport, ipto[0], ipto[1], ipto[2], ipto[3], ntohs(tcpconn.dport));
                memcpy(tcp_conn_client, &tcpconn, sizeof(struct tcpconn__ProcessConnEBPF));
            } else {
                return -2;
            }
            return 1;
        } else {
            return 0;
        }
    } else {
        return -1;
    }
}

int cleanAll_ProcessConnEBPF() {
    logdebug("CLEANING cleanAll_ProcessConnEBPF\n");
    bpf_link__destroy(gLinkProgRetProbe);
    bpf_link__destroy(gLinkProgProbe);
    bpf_object__close(gBpfObj);
    logdebug("CLEANING cleanAll_ProcessConnEBPF-2\n");
    return 0;
}

