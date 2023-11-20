/*
 * HTTPInterpreter.h
 *
 *  Created on: Nov 30, 2022
 *      Author: rodolk
 */

#ifndef HTTP_PROCESSING_HTTPINTERPRETER_H_
#define HTTP_PROCESSING_HTTPINTERPRETER_H_

#include <cstdint>
#include <vector>
#include <stdio.h>


#include "skb.h"
#include "TCPSegmentIterator.h"
#include "daemonLog.h"
#include "httpMsg.h"
#include "env.h"

extern DaemonLog *daemonLogging;

#define HTTP_PROCESSOR_CONTENT_LEN_ERR -2
#define HTTP_PROCESSOR_METHOD_ERR -1
#define HTTP_PROCESSOR_MSG_HDR_END 0
#define HTTP_PROCESSOR_MSG_HDR_INCOMPLETE 1
#define HTTP_PROCESSOR_MSG_BODY_EXTRALENGTH_ERROR -1
#define HTTP_PROCESSOR_MSG_BODY_COMPLETE 0
#define HTTP_PROCESSOR_MSG_BODY_INCOMPLETE 1

#define HTTP_METHOD_POST "POST"
#define HTTP_METHOD_GET "GET"

class HTTPInterpreter {
public:
    enum State_t {start_t, communicating_t, end_t, error_t};
    struct dataChunk_t {
        const uint8_t *data;
        uint16_t len;
        dataChunk_t(const uint8_t *dp, uint16_t l) : data(dp), len(l) {}
    };

    virtual ~HTTPInterpreter();
    HTTPInterpreter(skb_t *skb) : skb_(skb), tcpSgmtIter_(*(new TCPSegmentIterator(skb)))  {
        skb_->httpInterpreter = this;
        msgPayloadVector_.clear();
        auto envFound = gEnvVarsMap.find(SEARCH_HTTP_HEADER);
        if (envFound != gEnvVarsMap.end()) {
            httpHdrEnabled_ = true;
            httpHeaderSearch_ = envFound->second;
        }
        auto envFound2 = gEnvVarsMap.find(AVOID_LIVENESS_PROBE);
        if (envFound2 != gEnvVarsMap.end()) {
            avoidHdrEnabled_ = true;
            httpHeaderAvoid_ = envFound2->second;
        }
    }
    HTTPInterpreter(skb_t *skb, uint16_t tcpPayloadStart) : skb_(skb), tcpSgmtIter_(*(new TCPSegmentIterator(skb)))  {
        skb_->httpInterpreter = this;
        skb_->firstTCPPayloadByte = tcpSgmtIter_.getOffsetLastSegment() + tcpPayloadStart;
        auto envFound = gEnvVarsMap.find(SEARCH_HTTP_HEADER);
        if (envFound != gEnvVarsMap.end()) {
            httpHdrEnabled_ = true;
            httpHeaderSearch_ = envFound->second;
        }
        auto envFound2 = gEnvVarsMap.find(AVOID_LIVENESS_PROBE);
        if (envFound2 != gEnvVarsMap.end()) {
            avoidHdrEnabled_ = true;
            httpHeaderAvoid_ = envFound2->second;
        }
    }

    void process();

    void checkHTTP();
    bool isComplete() {return (state_ == communicating_t);}

    int processInitialHTTPHdr(char *httpHdrData, HTTPMsg &httpMsg, char *&nxtChar, const char *methodEndpoint, uint8_t methodEndPointLen);
    int processRestOfHTTPHdr(const char *httpHdrData, HTTPMsg &httpMsg, uint16_t len, const char *&nxtCharBody, const char *methodEndpoint, uint8_t methodEndPointLen, bool strcopy);
    int processHTTPBody(HTTPMsg& httpMsg, const char *&outBodyData);

private:
    skb_t *skb_;
    TCPSegmentIterator& tcpSgmtIter_;
    std::vector<dataChunk_t> msgPayloadVector_;
    HTTPMsg httpMsg_;
    State_t state_{start_t};
    bool processHdr_{true};
    bool httpHdrEnabled_{false};
    bool avoidHdrEnabled_{false};
    int msgMarkedWithError_{0};
    std::string httpHeaderSearch_;
    std::string httpHeaderAvoid_;
};

#endif /* HTTP_PROCESSING_HTTPINTERPRETER_H_ */
