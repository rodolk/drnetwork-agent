/*
 * HTTPInterpreter.cpp
 *
 *  Created on: Nov 30, 2022
 *      Author: rodolk
 */

#include "HTTPInterpreter.h"

#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

#include "httpMsg.h"

#define CONTENT_HDR_VALUE_LEN 3

#define HTTP_CONTENT_HDR "Content-Length: "
#define HTTP_CONTENT_HDR_LEN 16
#define HTTP_END_OF_L "\r\n"


HTTPInterpreter::~HTTPInterpreter() {
    // TODO Auto-generated destructor stub
}



void HTTPInterpreter::process() {
    uint16_t len = 1500;
    bool moreDataAvailable;
    const char *httpData;
    const char *nextCharToProcessBody;
    const char *nextCharToProcessBody2;
    int result = 0;
    const char *methodSpace = HTTP_METHOD_POST;

    if (state_ == error_t || state_ == communicating_t) {
        return;
    }

    bool processAgain = true;
    while(processAgain) {
        httpData = (const char *)tcpSgmtIter_.getTCPSegmentData(len, moreDataAvailable);
        if (len > 0) {
            if (processHdr_) {
                result = processRestOfHTTPHdr(httpData, httpMsg_, len, nextCharToProcessBody, methodSpace, strlen(methodSpace), true);
                if (result == HTTP_PROCESSOR_METHOD_ERR) {
                    methodSpace = HTTP_METHOD_GET;
                    result = processRestOfHTTPHdr(httpData, httpMsg_, len, nextCharToProcessBody, methodSpace, strlen(methodSpace), false);
                }
                if (result == HTTP_PROCESSOR_MSG_HDR_END) {
                    processHdr_ = false;
                    //TODO: look at this
                    if (start_t == state_) {
                        if (avoidHdrEnabled_ && httpMsg_.containsHeader(httpHeaderAvoid_.c_str())) {
                            //Reset follow mark
                            RESET_MARKED_FOR_DUMP(skb_);
                            removeMarkedForDump(skb_);
                        }
                        //If it contains searched header then we mark it for dump and override the RESET above
                        if (httpHdrEnabled_ && httpMsg_.containsHeader(httpHeaderSearch_.c_str())) {
                            //If it was marked for dump before, it doesn't change
                            SET_MARKED_FOR_DUMP(skb_);
                            addMarkedForDump(skb_);
                        }
                    }

                    result = processHTTPBody(httpMsg_, nextCharToProcessBody2);
                    if (result == HTTP_PROCESSOR_MSG_BODY_COMPLETE) {
                        state_ = communicating_t;
                        processHdr_ = true;
                        processAgain = false;
                    } else if (result == HTTP_PROCESSOR_MSG_BODY_INCOMPLETE) {
                        if (moreDataAvailable) {
                            len = 1500;
                            processAgain = true;
                        } else {
                            processAgain = false;
                        }
                    } else {
                        msgMarkedWithError_ = result;
                        state_ = error_t;
                        processAgain = false;
                    }
                } else {
                    if (result == HTTP_PROCESSOR_MSG_HDR_INCOMPLETE) {
                        if (moreDataAvailable) {
                            len = 1500;
                            processAgain = true;
                        } else {
                            processAgain = false;
                        }
                    } else {
                        msgMarkedWithError_ = result;
                        state_ = error_t;
                        processAgain = false;
                    }
                }
            } else {
                int res = httpMsg_.setHttpData(httpData, len);
                if (res == 0) {
                    result = processHTTPBody(httpMsg_, nextCharToProcessBody2);
                    if (result == HTTP_PROCESSOR_MSG_BODY_COMPLETE) {
                        state_ = communicating_t;
                        processHdr_ = true;
                        processAgain = false;
                    } else if (result == HTTP_PROCESSOR_MSG_BODY_INCOMPLETE) {
                        if (moreDataAvailable) {
                            len = 1500;
                            processAgain = true;
                        } else {
                            processAgain = false;
                        }
                    } else {
                        msgMarkedWithError_ = result;
                        state_ = error_t;
                        processAgain = false;
                    }
                } else {
                    msgMarkedWithError_ = -10; //Max amount of data passed
                    state_ = error_t;
                    processAgain = false;
                }
            }
        } else {
            //len <= 0
            if (moreDataAvailable) {
                len = 1500;
                processAgain = true;
            } else {
                processAgain = false;
            }
        }
    }
}

/**
 * This method must be called as soon as the first TCP message with payload is received,
 * usually after TCP handshake.
 * It will call tcpSgmtIter_.getFirstPayloadOctet which will initialize the iterator, returns the first Octet,
 * and moves the iterator to the next position in the first TCP payload.
 * The we check various Bytes to check if it carries a HTTP message.
 * This method also initializes internal variables to parse TLS messages.
 *
 * WARNING: Here I', making it easy and I assume the first data segment brings a minimum of 3 Bytes. However,
 * TCP could send a segment without data or with only 1 or 2 octets. This would generate an error in our code.
 * TODO: fix this
 */
void HTTPInterpreter::checkHTTP() {
    char buff[3];
    uint8_t firstOctet = tcpSgmtIter_.getFirstPayloadOctet();
    skb_->isHTTPDecision = 0;
    if (firstOctet > ('A' - 1) && firstOctet < ('Z' - 1)) {
        uint8_t secondOctet = tcpSgmtIter_.getNextPayloadOctet();
        if (secondOctet > ('A' - 1) && secondOctet < ('Z' - 1)) {
            uint8_t thirdOctet = tcpSgmtIter_.getNextPayloadOctet();
            if (thirdOctet > ('A' - 1) && thirdOctet < ('Z' - 1)) {
                if (firstOctet == 'G' && secondOctet == 'E' && thirdOctet == 'T') {
                    skb_->isHTTPDecision = 1;
                    buff[0] = 'G';
                    buff[1] = 'E';
                    buff[2] = 'T';
                    httpMsg_.setHttpData(buff, 3);
                } else if (firstOctet == 'P' && secondOctet == 'O' && thirdOctet == 'S') {
                    skb_->isHTTPDecision = 1;
                    buff[0] = 'P';
                    buff[1] = 'O';
                    buff[2] = 'S';
                    httpMsg_.setHttpData(buff, 3);
                }
                process();
            } else {
                skb_->isHTTPDecision = 2;
            }
        } else {
            skb_->isHTTPDecision = 2;
        }
    } else {
        skb_->isHTTPDecision = 2;
    }
}


/**********************************************************************************************************************
 * Name: processInitialHTTPHdr
 * Description: This function is called for processing an HTTP header for first time. The header could be complete or
 * partial. If it is partial, INCOMPLETE will be returned and, when the next part of the header is received, it will be
 * passed to function processRestOfHTTPHdr. This function (processInitialHTTPHdr) is called only the first time.
 *
 * Arguments:
 * char *   httpHdrData Pointer to C String containing received header data
 * HTTPMsg& httpMsg     HTTP msg being received and processed
 * char *&  nxtChar     out pointer to the next char to be processed. It will point to the edn of header chars
 *                      if the header is complete.
 * int&     contentLen  Value of ContentLength header if it is found in the data received.
 *
 * Returns
 * int              result of HDR processing
 *                  HTTP_PROCESSOR_MSG_HDR_END
 *                  HTTP_PROCESSOR_MSG_HDR_INCOMPLETE
 *                  HTTP_PROCESSOR_CONTENT_LEN_ERR
 *                  HTTP_PROCESSOR_METHOD_ERR
 *
 * Note:
 * httpHdrData must be NULL terminated C String.
 *********************************************************************************************************************/
int HTTPInterpreter::processInitialHTTPHdr(char *httpHdrData, HTTPMsg &httpMsg, char *&nxtChar, const char *methodEndpoint, uint8_t methodEndPointLen)
{
    char *ptr = httpHdrData;
    char *contentPtr;
    char *methodPtr;
    char *auxPtr;
    char *endOfHdr;
    char *eol;
    int res;
    int contentLen;

    methodPtr = strstr(ptr, methodEndpoint);

    if (methodPtr)
    {
        httpMsg.setMethodFound();
        ptr += methodEndPointLen;
        contentPtr = strstr(ptr, HTTP_CONTENT_HDR);

        if (contentPtr)
        {
            eol = strstr(contentPtr, HTTP_END_OF_L);
            if (eol)
            {
                *eol = 0;
                httpMsg.setContentHdrFound();
                errno = 0;
                contentLen = strtol(contentPtr + HTTP_CONTENT_HDR_LEN, &auxPtr, 10);

                if (contentLen == 0)
                {
                    if (!(*auxPtr == 0 && errno == 0))
                    {
                        return HTTP_PROCESSOR_CONTENT_LEN_ERR;
                    }
                }

                httpMsg.setContentLen(contentLen);

                *eol = '\r';
                endOfHdr = strstr(eol, HTTP_END_OF_HDR);

                if (endOfHdr)
                {
                    nxtChar = endOfHdr;
                    res = HTTP_PROCESSOR_MSG_HDR_END;
                }
                else
                {
                    nxtChar = eol;
                    httpMsg.setHttpData(eol);
                    res = HTTP_PROCESSOR_MSG_HDR_INCOMPLETE;
                }
            }
            else
            {
                nxtChar = contentPtr;
                httpMsg.setHttpData(contentPtr);
                res = HTTP_PROCESSOR_MSG_HDR_INCOMPLETE;
            }
        }
        else
        {
            //Content header may not be included in the HDR
            endOfHdr = strstr(ptr, HTTP_END_OF_HDR);

            if (endOfHdr)
            {
                nxtChar = endOfHdr;
                res = HTTP_PROCESSOR_MSG_HDR_END;
            }
            else
            {
                nxtChar = ptr;
                httpMsg.setHttpData(ptr);
                res = HTTP_PROCESSOR_MSG_HDR_INCOMPLETE;
            }
        }
    }
    else
    {
        if (!(strlen(ptr) < strlen(methodEndpoint)))
        {
            res = HTTP_PROCESSOR_METHOD_ERR;
        }
        else
        {
            httpMsg.setHttpData(ptr);
            nxtChar = ptr;
            res = HTTP_PROCESSOR_MSG_HDR_INCOMPLETE;
        }
    }

    return res;
}


/**********************************************************************************************************************
 * Name: processRestOfHTTPHdr
 * Description: This function is called for processing an HTTP header when the rest of the header data is received and
 * after calling processInitialHTTPHdr for first time. The header could be complete or still partial.
 *
 * Arguments:
 * char *   httpHdrData Pointer to C String containing received header data
 * HTTPMsg& httpMsg     HTTP msg being received and processed
 * char *&  nxtChar     out pointer to the next char to be processed. It will point to the edn of header chars
 *                      if the header is complete.
 * int&     contentLen  Value of ContentLength header if it is found in the data received.
 *
 * Returns
 * int              result of HDR processing
 *                  HTTP_PROCESSOR_MSG_HDR_END
 *                  HTTP_PROCESSOR_MSG_HDR_INCOMPLETE
 *                  HTTP_PROCESSOR_CONTENT_LEN_ERR
 *                  HTTP_PROCESSOR_METHOD_ERR
 *
 * Note:
 * httpHdrData must be NULL terminated C String.
 *********************************************************************************************************************/
int HTTPInterpreter::processRestOfHTTPHdr(const char *httpData, HTTPMsg &httpMsg, uint16_t len, const char *&nxtCharBody,
        const char *methodEndpoint, uint8_t methodEndPointLen, bool strcopy) {
    char *ptr;
    char *contentPtr;
    char *methodPtr;
    char *auxPtr;
    char *endOfHdr;
    char *eol;
    int contentLen;

    if (strcopy) {
        int res1 = httpMsg.setHttpData(httpData, len);
        if (res1 != 0) return -10;
    }
    ptr = (char *)httpMsg.getData();

    if (!httpMsg.getMethodFound()) {
        methodPtr = strstr(ptr, methodEndpoint);

        if (methodPtr) {
            httpMsg.setMethodFound();
            ptr += methodEndPointLen;
        } else {
            if (!(strlen(ptr) < strlen(methodEndpoint))) {
                return HTTP_PROCESSOR_METHOD_ERR;
            } else {
                return HTTP_PROCESSOR_MSG_HDR_INCOMPLETE;
            }
        }
    } //else continue

    if (!httpMsg.getContentHdrFound()) {
        contentPtr = strstr(ptr, HTTP_CONTENT_HDR);

        if (contentPtr) {
            eol = strstr(contentPtr, HTTP_END_OF_L);
            if (eol) {
                *eol = 0;
                httpMsg.setContentHdrFound();
                errno = 0;
                contentLen = strtol(contentPtr + HTTP_CONTENT_HDR_LEN, &auxPtr, 10);

                if (contentLen == 0) {
                    if (!(*auxPtr == 0 && errno == 0)) {
                        return HTTP_PROCESSOR_CONTENT_LEN_ERR;
                    }
                }

                httpMsg.setContentLen(contentLen);

                *eol = '\r';
                ptr = eol;
            }
            else {
                return HTTP_PROCESSOR_MSG_HDR_INCOMPLETE;
            }
        } //else continue - the message might not have content header
    }  //else continue

    endOfHdr = strstr(ptr, HTTP_END_OF_HDR);

    if (endOfHdr) {
        nxtCharBody = endOfHdr;
        return HTTP_PROCESSOR_MSG_HDR_END;
    }
    else {
        return HTTP_PROCESSOR_MSG_HDR_INCOMPLETE;
    }
}

/**********************************************************************************************************************
 * Name: processHTTPBody
 * Description: This function processes HTTP body. If the body comes in different TCP messages, it will gather all
 * chunks until body is completed. An error is returned if the body length is detected to be longer than Content Len.
 *
 * Arguments:
 * char *   httpBodyData    Pointer to C String containing received body data
 * HTTPMsg& httpMsg         HTTP msg being received and processed
 * char *&  outBodyData     in/out pointer to the returned body data once the WHOLE and HEALTHY body was received
 *
 * Returns
 * int              result of body processing (COMPLETE, INCOMPLETE, ERROR)
 *
 * Note:
 * Body data received must be NULL terminated. Also outBodyData.
 * It is assumed body does not finish with '\r\n'
 *********************************************************************************************************************/
int HTTPInterpreter::processHTTPBody(HTTPMsg& httpMsg, const char *&outBodyData) {
    uint16_t bodyLen = httpMsg.getBodyLen(); //httpBodyData always begins with \r\n\r\n
    outBodyData = httpMsg.getBodyData();
    if (bodyLen == httpMsg.getContentLen()) {
        return HTTP_PROCESSOR_MSG_BODY_COMPLETE;
    } else {
        if (bodyLen < httpMsg.getContentLen()) {
            return HTTP_PROCESSOR_MSG_BODY_INCOMPLETE;
        } else {
            return HTTP_PROCESSOR_MSG_BODY_EXTRALENGTH_ERROR;
        }
    }
}

