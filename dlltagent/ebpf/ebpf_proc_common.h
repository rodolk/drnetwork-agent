/*
 * ebpf_proc_common.h
 *
 *  Created on: Jan 3, 2022
 *      Author: rodolk
 */

#ifndef EBPF_EBPF_PROC_COMMON_H_
#define EBPF_EBPF_PROC_COMMON_H_

#include <stdint.h>

#define COMM_LEN_PROCESS_CONN_EBPF 32

struct tcpconn__ProcessConnEBPF {
    int32_t tgid;
    int32_t pid;
    int32_t ppid;
    uint32_t uid;
    uint16_t lport;
    uint16_t dport;
    uint32_t saddr;
    uint32_t daddr;
    char comm[COMM_LEN_PROCESS_CONN_EBPF];
};



#endif /* EBPF_EBPF_PROC_COMMON_H_ */
