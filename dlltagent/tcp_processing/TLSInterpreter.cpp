/*
 * TLSInterpreter.cpp
 *
 *  Created on: Apr 3, 2020
 *      Author: rodolk
 */

#include "TLSInterpreter.h"


TLSInterpreter::~TLSInterpreter() {
    delete &tcpSgmtIter_;
    delete state_;
}

/**
 * This method must be called as soon as the first TCP message with payload is received,
 * usually after TCP handshake.
 * It will call tcpSgmtIter_.getFirstPayloadOctet which will initialize the iterator, returns the first Octet,
 * and moves the iterator to the next position in the first TCP payload.
 * The we check various Bytes to check if it carries a TLS message to initiate a connection.
 * This method also initializes internal variables to parse TLS messages.
 *
 */
void TLSInterpreter::checkTLS() {
    TLSRecordType_t tlsType = (TLSRecordType_t)tcpSgmtIter_.getFirstPayloadOctet();
    skb_->isTLS = 0;
    if (tlsType == TLS_HANDSHAKE || tlsType == TLS_ALERT) {
        uint8_t octet = tcpSgmtIter_.getNextPayloadOctet();
        if (octet == kVersionMajor) {
            octet = tcpSgmtIter_.getNextPayloadOctet();
            if (octet < kVersionMinorMaxPlusOne) {
                currRecordProtocolPloadLen_ = (uint16_t)tcpSgmtIter_.getNextPayloadOctet() << 8|
                        (uint16_t)tcpSgmtIter_.getNextPayloadOctet();
                skb_->isTLS = 1;
                currRecordProtocolPloadReadSoFar__ = 0;
                readingNextRPHdr_ = false;
                currHLProtocolMsg_ = tlsType;
                process();
            }
        }
    }
}




/**
 * Reads a TLS record header.
 * It can read it completely if all Octets are there or partially.
 * Uses tcpSgmtIter_ to read the header.
 * When partial header is read, currRecordProtocolHdrReadSoFar_ is updated.
 * Data is copied to currRecordProtocolHdr as it is read.
 *
 * @return different values depending on whether the header was read:
 *          -0: The complete header was read and there is not more data available
 *          -2: The complete header was read and there is more data available
 *          -1: The header was partially read and there is no more data available.
 *              The method has to be called again.
 */
uint8_t TLSInterpreter::readRecordProtocolHdr() {
    uint16_t len = currRecordProtocolHdrLen_ - currRecordProtocolHdrReadSoFar_;
    uint16_t requestedLen = len;
    bool moreDataAvailable;
    const uint8_t *tlsData;
    uint8_t result = 0;
    while(requestedLen > 0) {
        tlsData = tcpSgmtIter_.getTCPSegmentData(len, moreDataAvailable);
        if (len > 0) {
            memcpy(currRecordProtocolHdr + currRecordProtocolHdrReadSoFar_, tlsData, len);
        }
        if (requestedLen == len) {
            currRecordProtocolHdrReadSoFar_ = 0;
            requestedLen = 0;
            if (!moreDataAvailable) {
                result = 0;
            } else {
                result = 2;
            }
        } else {
            currRecordProtocolHdrReadSoFar_ += len;
            if (moreDataAvailable) {
                len = currRecordProtocolHdrLen_ - currRecordProtocolHdrReadSoFar_;
                requestedLen = len;
            } else {
                requestedLen = 0;
                result = 1;
            }
        }
    }
    return result;
}


/**
 * Reads any TLS protocol payload.
 * It can read it completely if all Octets are there or partially.
 * Uses tcpSgmtIter_ to read the payload.
 * When partial read is read, currRecordProtocolPloadReadSoFar__ is updated.
 * tcpSgmtIter_.getTCPSegmentData returns a pointer to the data read and len will indicate the amount of data.
 * If data is needed by the caller, readData is true, then the data chunks will be stored in msgPayloadVector_
 * as dataChunk_t. Then the caller will have access to the data.
 *
 * @param readData indicates if data is to be needed by the caller
 *
 * @return different values depending on whether the header was read:
 *          -0: The complete payload was read and there is not more data available
 *          -2: The complete payload was read and there is more data available
 *          -1: The payload was partially read and there is no more data available.
 *              The method has to be called again.
 */
uint8_t TLSInterpreter::readCompleteCurrHLProtocolMsg(bool readData) {
    uint16_t len = currRecordProtocolPloadLen_ - currRecordProtocolPloadReadSoFar__;
    uint16_t requestedLen = len;
    bool moreDataAvailable;
    const uint8_t *tlsHLProtocolMsg;
    uint8_t result = 0;

    while(requestedLen > 0) {
        tlsHLProtocolMsg = tcpSgmtIter_.getTCPSegmentData(len, moreDataAvailable);
        if (requestedLen == len) {
            currRecordProtocolPloadReadSoFar__ = 0;
            requestedLen = 0;
            if (readData) {
                dataChunk_t dc(tlsHLProtocolMsg, len);
                msgPayloadVector_.push_back(dc);
            }
            if (!moreDataAvailable) {
                result = 0; //We read the whole frame
            } else {
                result = 2;
            }
        } else {
            if (readData && len > 0) {
                dataChunk_t dc(tlsHLProtocolMsg, len);
                msgPayloadVector_.push_back(dc);
            }
            currRecordProtocolPloadReadSoFar__ += len;
            if (moreDataAvailable) {
                len = currRecordProtocolPloadLen_ - currRecordProtocolPloadReadSoFar__;
                requestedLen = len;
            } else {
                requestedLen = 0;
                result = 1;
            }
        }
    }
    return result;
}
