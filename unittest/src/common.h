/*
 * common.h
 *
 *  Created on: Jul 6, 2021
 *      Author: rodolk
 */

#ifndef COMMON_H_
#define COMMON_H_

#include <cstdint>

/*
 * CAUTION!!!!!!!
 * UT is done with this fix BUFFER_SIZE = (1024 * 1024)
 * TODO: Fix unit test to be able to deal with a variable BUFFER_SIZE
 */

#define MAX_MSG_LEN 10000
typedef struct buffer
{
    uint8_t msg[MAX_MSG_LEN];
    struct pcap_pkthdr hdr;
    uint8_t status;
    uint16_t len;
} msg_buffer_t;


#define ETHER_DEFAULT_HDR_LEN 14

#ifdef SKB_MAX_COUNT_FB
#undef SKB_MAX_COUNT_FB
#endif

#define SKB_MAX_COUNT_FB 10

extern bool firstTime;
extern uint16_t gSkbMaxCountFB;

skb_t *storePacket(msg_buffer_t *msgBuf);


#endif /* COMMON_H_ */
