/*
 * flow.h
 *
 *  Created on: May 28, 2021
 *      Author: rodolk
 */

#ifndef FLOW_H_
#define FLOW_H_

#include <stdint.h>

#include "ipconst.h"

#define SHORT_NAME_LEN 32

typedef struct {
    int32_t  pid;
    int32_t  ppid;
    uint32_t uid;
    char shortName[SHORT_NAME_LEN + 1];
} flow_process_t;

typedef struct {
    uint16_t portSrc;
    uint16_t portDst;
    uint8_t  ipSrc[IPV4_ADDR_LEN];
    uint8_t  ipDst[IPV4_ADDR_LEN];
    flow_process_t process;
    char     fromInternet;
    struct timeval timeStamp;
} flow_t;

typedef struct {
    struct timeval initTimeStamp;
    struct timeval endTimeStamp;
    uint64_t dataFrom;
    uint64_t dataTo;
    uint32_t latency1;
    uint32_t latency2;
    uint32_t latency3;
    uint8_t connType;
    uint8_t quality;
    uint8_t evtSrc;
    uint8_t endType;
} common_evt_t;

typedef struct {
    //Caution: Do not change order of first 4 elements, coupled with other structs
    uint16_t portSrc;
    uint16_t portDst;
    uint8_t ipSrc[IPV4_ADDR_LEN];
    uint8_t ipDst[IPV4_ADDR_LEN];
    common_evt_t cevt;
    flow_process_t process;
} end_flow_t;


#endif /* FLOW_H_ */
