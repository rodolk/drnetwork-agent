/*
 * TLSFirstState.h
 *
 *  Created on: Apr 6, 2020
 *      Author: rodolk
 */

#ifndef TLSFIRSTSTATE_H_
#define TLSFIRSTSTATE_H_

#include "TLSState.h"
#include "TLSHandshakeState.h"
#include "TLSAlertState.h"

class TLSFirstState: public TLSState {
public:
    TLSFirstState(TLSInterpreter *tlsInterp) : TLSState(tlsInterp) {}
    virtual ~TLSFirstState();

    virtual TLSState *process(bool& processAgain) {
        processAgain = false;
        TLSRecordType_t type = getcurrHLMsgType();
        switch(type) {
        case TLS_HANDSHAKE:
            return new TLSHandshakeState(tlsInterp_);
        case TLS_ALERT:
            return new TLSAlertState(tlsInterp_);
        default:
            return nullptr;
        }
    }
    virtual TLSState *processSpecific(TLSRecordType_t tlsRecType) {
        return this;
    }

    virtual TLSState *init() {
        return this;
    }

};

#endif /* TLSFIRSTSTATE_H_ */
