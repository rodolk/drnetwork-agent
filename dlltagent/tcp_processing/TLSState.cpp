/*
 * TLSState.cpp
 *
 *  Created on: Apr 6, 2020
 *      Author: rodolk
 */
#include <stdio.h>
#include "TLSState.h"

#include "TLSInterpreter.h"


TLSState::~TLSState() {
    // TODO Auto-generated destructor stub
}

/**
 * Call to tlsInterp_->readRecordProtocolHdr can return 3 possible values. Refer to its comment for
 * understanding the meaning. 0 or 2 mean the complete header was read.
 * When there is no more data available result from tlsInterp_->readRecordProtocolHdr or
 * tlsInterp_->readCompleteCurrHLProtocolMsg will return 0 or 1. In this case it is not necessary
 * to process again until a new message is captured.
 *
 * result values:
 * -0: we read what was requested and there is no more data to read in the frame
 * -1: we may have read part of the data, not all requested data, and there is no more data to read
 * -2: we read all requested data and there is more data in the frame
 * -3: we must not read a TLS header, we need to read TLS payload data
 *
 * If result is 2 at the end, processAgain must be set to true
 */
TLSState *TLSState::process(bool& processAgain) {
    uint8_t result = 3;
    TLSState *nextState = this;
    if (tlsInterp_->readingNextRPHdr_) {
        result = tlsInterp_->readRecordProtocolHdr();
        if (result == 0 || result == 2) {
            tlsInterp_->readingNextRPHdr_ = false;
            tlsInterp_->currRecordProtocolPloadLen_ = (uint16_t)tlsInterp_->currRecordProtocolHdr[3]<<8 |
                    (uint16_t)tlsInterp_->currRecordProtocolHdr[4];
            tlsInterp_->currRecordProtocolPloadReadSoFar__ = 0;
            TLSRecordType_t tlsRecType =
                    (TLSRecordType_t)tlsInterp_->currRecordProtocolHdr[0];

            if (tlsRecType < TLS_CHANGE_CIPHER_SPEC || tlsRecType > TLS_APPLICATION_DATA) {
                throw TLSException(TLSState::kExceptionUnexpectedMessage);
            } else {
                nextState = processSpecific(tlsRecType);
            }
        } // else (result == 1): continue reading RPHdr in next process
    }
    //Only if result is 2 or 3, we may enter here
    if (result > 1 && !tlsInterp_->readingNextRPHdr_) {
        //TODO: Here we are creating and destroying memory. Can we work with a preexisting allocation?
        //TODO: Like keeping 10 elements all the time?
        //Only if we are about to begin to read the msg payload
        if (result == 2 && nextState->requiresDataRead()) tlsInterp_->msgPayloadVector_.clear();

        result = tlsInterp_->readCompleteCurrHLProtocolMsg(nextState->requiresDataRead());
        if (result == 0 || result == 2) {
            try {
                nextState->processPayload();
            } catch(TLSAlertException& excep) {
                if (nextState != this) {
                    delete nextState; //delete to avoid memory leak after the exception
                }
                throw;
            }
            tlsInterp_->readingNextRPHdr_ = true;
        }
    }
    if (result == 2) {
        processAgain = true;
    } else {
        processAgain = false;
    }
    return nextState;
}

TLSRecordType_t TLSState::getcurrHLMsgType() {
    return tlsInterp_->currHLProtocolMsg_;
}

void TLSState::setReadingNextRPHdr(bool state) {
    tlsInterp_->readingNextRPHdr_ = state;
}

bool TLSState::prepareBytes(uint16_t numReqBytes) {
    TLSInterpreter::dataChunk_t dc(nullptr, 0);
    uint16_t totBytes = 0;
    uint8_t idx = 0;
    while(totBytes < numReqBytes && tlsInterp_->msgPayloadVector_.size() > idx) {
        dc = tlsInterp_->msgPayloadVector_[idx];
        totBytes += dc.len;
        idx++;
    }
    if (totBytes < numReqBytes) {
        return false;
    }
    return true;
}

const uint8_t *TLSState::getBytes(uint8_t idx, uint16_t &numBytes) {
    TLSInterpreter::dataChunk_t dc(nullptr, 0);
    if (tlsInterp_->msgPayloadVector_.size() > idx) {
        dc = tlsInterp_->msgPayloadVector_[idx];
        numBytes = dc.len;
        return dc.data;
    } else {
        numBytes = 0;
        return nullptr;
    }
}


uint16_t TLSState::getSrcPort() {
    return tlsInterp_->skb_->portSrc;
}
uint16_t TLSState::getDstPort() {
    return tlsInterp_->skb_->portDst;
}

uint16_t TLSState::getPayloadLen() {
    return tlsInterp_->currRecordProtocolPloadLen_;
}
