/*
 * skb.h
 *
 *  Created on: Mar 4, 2020
 *      Author: rodolk
 */

#ifndef SKB_H_
#define SKB_H_

#include <stdint.h>
#include <pthread.h>

#include <map>
#include <list>

#include "frameBuffer.h"
#include "ipconst.h"
#include "timeHelper.h"

#define SKB_STATE_CNT_MASK     0x0F
//SKB_STATE_CNT_MASK counter is reused for SKB_KEEPALIVE_CNT_MASK: when SKB_KEEPALIVE_CNT_MASK is used, SKB_STATE_CNT_MASK cannot be used
//#define SKB_KEEPALIVE_CNT_MASK 0x0F
//#define SKB_RESEND_CNT_MASK    0xF0
#define SKB_ORPHAN_CNT_MASK    0x0F

/* Do not use these raw values outside this file */
/* Values for state */
#define SKB_DUMPING                0x01
#define SKB_MARKED_FOR_DUMP        0x02
#define SKB_STATE_KILLED           0x04
#define SKB_STATE_KILLED_DELETED   0x08
#define SKB_NOTIFICATION_SENT      0x10
#define SKB_FB_WRAP_AROUND         0x20
#define SKB_SKB_DUMP_PENDING       0x40
#define SKB_DO_NOT_PARSE           0x80

/* Values for state2 */
#define SKB_PID_SEARCH             0x01

//#define SKB_HTTP_HEADER_SENT       0x20
//#define SKB_HTTP_HEADER_TO_RESEND       0x40 //If first header needs to be resent

#define IS_SKB_NOTIFICATION_SENT(skbarg) ((skbarg)->state & SKB_NOTIFICATION_SENT)
#define SET_SKB_NOTIFICATION_SENT(skbarg) ((skbarg)->state |= SKB_NOTIFICATION_SENT)
#define RESET_SKB_NOTIFICATION_SENT(skbarg) ((skbarg)->state &= ~SKB_NOTIFICATION_SENT)

#define RESET_STATE(skbarg) ((skbarg)->state = 0)

#define IS_SKB_STATE_KILLED(skbarg) ((skbarg)->state & SKB_STATE_KILLED)
#define SET_SKB_STATE_KILLED(skbarg) ((skbarg)->state |= SKB_STATE_KILLED)
#define RESET_SKB_STATE_KILLED(skbarg) ((skbarg)->state &= ~SKB_STATE_KILLED)

#define IS_SKB_KILLED_DELETED(skbarg) ((skbarg)->state & SKB_STATE_KILLED_DELETED)
#define SET_SKB_KILLED_DELETED(skbarg) ((skbarg)->state |= SKB_STATE_KILLED_DELETED)

#define IS_SKB_FB_WRAP_AROUND(skbarg) ((skbarg)->state & SKB_FB_WRAP_AROUND)
#define SET_SKB_FB_WRAP_AROUND(skbarg) ((skbarg)->state |= SKB_FB_WRAP_AROUND);

#define IS_SKB_DUMP_PENDING(skbarg) ((skbarg)->state & SKB_SKB_DUMP_PENDING)
#define SET_SKB_DUMP_PENDING(skbarg) ((skbarg)->state |= SKB_SKB_DUMP_PENDING);
#define RESET_SKB_DUMP_PENDING(skbarg) ((skbarg)->state &= ~SKB_SKB_DUMP_PENDING);

#define IS_SKB_DUMPING(skbarg) ((skbarg)->state & SKB_DUMPING)
#define SET_SKB_DUMPING(skbarg) ((skbarg)->state |= SKB_DUMPING)
#define RESET_SKB_DUMPING(skbarg) ((skbarg)->state &= ~SKB_DUMPING)

//#define IS_SKB_HTTP_HEADER_SENT(skbarg) ((skbarg)->state & SKB_HTTP_HEADER_SENT)
//#define IS_SKB_HTTP_HEADER_TO_RESEND(skbarg) ((skbarg)->state & SKB_HTTP_HEADER_TO_RESEND)
//#define SET_SKB_HTTP_HEADER_SENT(skbarg) ((skbarg)->state |= SKB_HTTP_HEADER_SENT; (skbarg)->state |= SKB_HTTP_HEADER_TO_RESEND)
//#define RESET_SKB_HTTP_HEADER_SENT(skbarg) ((skbarg)->state &= ~SKB_HTTP_HEADER_SENT)
//#define RESET_SKB_HTTP_HEADER_TO_RESEND(skbarg) ((skbarg)->state &= ~SKB_HTTP_HEADER_TO_RESEND)

#define IS_KEEPALIVE_CNT_THR(skbarg, threshold) (((skbarg)->counter) >= threshold)
#define RESET_KEEPALIVE_CNT_MASK(skbarg) ((skbarg)->counter = 0);
//#define RESET_KEEPALIVE_CNT_MASK(skbarg) ((skbarg)->counter &= ~SKB_KEEPALIVE_CNT_MASK)
//Because KEEPALIVE_CNT is the first 4 bits I can increment de byte directly
//Caution: it the value is 0x0F I must not increment but reset
#define INC_KEEPALIVE_CNT_MASK(skbarg) ((skbarg)->counter++)

#define IS_MARKED_FOR_DUMP(skbarg) ((skbarg)->state & SKB_MARKED_FOR_DUMP)
#define SET_MARKED_FOR_DUMP(skbarg) ((skbarg)->state |= SKB_MARKED_FOR_DUMP)
#define RESET_MARKED_FOR_DUMP(skbarg) ((skbarg)->state &= ~SKB_MARKED_FOR_DUMP)


#define IS_DO_NOT_PARSE(skbarg) ((skbarg)->state & SKB_DO_NOT_PARSE)
#define SET_DO_NOT_PARSE(skbarg) ((skbarg)->state |= SKB_DO_NOT_PARSE)
#define RESET_DO_NOT_PARSE(skbarg) ((skbarg)->state &= ~SKB_DO_NOT_PARSE)

#define IS_SKB_PID_SEARCHING(skbarg) ((skbarg)->state2 & SKB_PID_SEARCH)
#define SET_SKB_PID_SEARCHING(skbarg) ((skbarg)->state2 |= SKB_PID_SEARCH)
#define RESET_SKB_PID_SEARCHING(skbarg) ((skbarg)->state2 &= ~SKB_PID_SEARCH)


#define MSG_SEQ_LEN 4
#define UNIQUE_DATA_LEN 8
#define UNIQUE_DATA_POS 12


typedef enum {
    SYN, SYN_ACK, LAST_HSHAKE_ACK, ESTABLISHED, FIN1, CLOSED
} con_status_t;

typedef enum {
    NONE=0, FIN1_DATA, RESET
} con_deviation_t;

class TLSInterpreter;
class HTTPInterpreter;

//#dep: there is code depending on ports and ip addresses being the first 4 fields
typedef struct usrSkb {
    //Caution: Do not change order of first 4 elements, coupled to event_t
    uint16_t portSrc;
    uint16_t portDst;
    uint8_t ipSrc[IPV4_ADDR_LEN];
    uint8_t ipDst[IPV4_ADDR_LEN];
    uint16_t origPortSrc;
    uint16_t origPortDst;
    uint8_t origIpSrc[IPV4_ADDR_LEN];
    uint8_t origIpDst[IPV4_ADDR_LEN];
    con_status_t cStatus;
    con_deviation_t cDeviation;
    struct timeval initialTime;
    uint32_t firstTCPPayloadByte;
    TLSInterpreter *tlsInterpreter;
    HTTPInterpreter *httpInterpreter;
    uint32_t latency1; //In usecs
    uint32_t latency2; //In usecs
    uint32_t latency3;
    uint32_t lastseq;
    uint32_t nextseq;
    uint32_t lastacked;
    uint32_t registeredSequence;
    int32_t  pid; //-1 means it wasn't associated to a process yet, -2 means it couldn't be associated to a process and won't search more
    uint64_t dataFrom;
    uint64_t dataTo;
    uint16_t countFB;
    uint16_t maxCountFB;
    uint16_t connType;
    uint8_t isTLS;
    uint8_t isHTTPDecision; //0: unknown, 1: http, 2:no_http
    uint8_t counter;
    uint8_t counter2;
    uint8_t state;
    uint8_t state2;
    uint8_t lastsent;
    uint8_t uniqueData[UNIQUE_DATA_LEN];
    uint8_t used;
    uint8_t syncRetries;
    uint8_t errorFrameBuffer;
    pthread_mutex_t skbmutex;
    //HTTPTypeMsg<HTTPRegistrationMsgType> *partialHTTPMsg;
    FrameBuffer *headFrameBuffer;
    FrameBuffer *currFrameBuffer;
    struct usrSkb *next;
    struct usrSkb *prev;
} skb_t;

skb_t* skbLookup(skb_t *auxSkb);
int addNewSkb(skb_t *auxSkb);
void initializeSkb();
skb_t* get_new_skb();
void logSkbManagementData();
inline bool isHTTP(skb_t *skb) {
    return (skb->isHTTPDecision == 1);
}

void addDataToSkb(skb_t *currSkb, uint8_t *data, size_t size);

inline void returnSkb(skb_t *skb) {
    skb->used--;
}

void moveSkbToEstablishedQ(skb_t *processedSkb);
int submitDeleteConnectingSkb(skb_t *processedSkb);
int submitDeleteEstablishedSkb(skb_t *processedSkb);
void shutdownSkb();

typedef struct masrkedForDump {
    skb_t *skb;
    struct timeval timeMarked;
} markedForDump_t;

void addMarkedForDump(skb_t *skb);
void removeMarkedForDump(skb_t *skb);
skb_t *processDumpRequired(uint16_t seconds);
void cleanMarkedForDump();
void calcLatency(skb_t *usrSkb, struct timeval *lastTime);

#endif /* SKB_H_ */
