/*
 * TLSApplicationDataState.cpp
 *
 *  Created on: Apr 13, 2020
 *      Author: rodolk
 */

#include "TLSApplicationDataState.h"

#include "TLSAlertState.h"

TLSApplicationDataState::~TLSApplicationDataState() {
    // TODO Auto-generated destructor stub
}

TLSState *TLSApplicationDataState::processSpecific(TLSRecordType_t tlsRecType) {
    TLSState *nextState = this;
    switch(tlsRecType) {
    case TLS_ALERT:
        nextState = new TLSAlertState(tlsInterp_, true);
        break;
    case TLS_APPLICATION_DATA:
        break;
    default:
        break;
    }
    return nextState;
}
