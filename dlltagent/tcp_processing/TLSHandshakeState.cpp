/*
 * TLSHandshakeState.cpp
 *
 *  Created on: Apr 6, 2020
 *      Author: rodolk
 */

#include "TLSHandshakeState.h"

#include "TLSAlertState.h"
#include "TLSApplicationDataState.h"
#include "TLSInterpreter.h"

TLSHandshakeState::~TLSHandshakeState() {
    // TODO Auto-generated destructor stub
}

TLSState *TLSHandshakeState::processSpecific(TLSRecordType_t tlsRecType) {
    TLSState *nextState = this;
    switch(tlsRecType) {
    case TLS_HANDSHAKE:
        break;
    case TLS_CHANGE_CIPHER_SPEC:
        break;
    case TLS_ALERT:
        nextState = new TLSAlertState(tlsInterp_);
        break;
    case TLS_APPLICATION_DATA:
        nextState = new TLSApplicationDataState(tlsInterp_);
        tlsInterp_->calcHShakeDoneLatency();
        tlsInterp_->handshakeDone = true;
        break;
    default:
        break;
    }
    return nextState;
}

