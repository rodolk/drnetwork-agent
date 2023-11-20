/*
 * TLSShutdownState.h
 *
 *  Created on: Apr 13, 2020
 *      Author: rodolk
 */

#ifndef TLSSHUTDOWNSTATE_H_
#define TLSSHUTDOWNSTATE_H_

#include <iostream>
#include "TLSState.h"

class TLSShutdownState: public TLSState {
public:
    TLSShutdownState(TLSInterpreter *tlsInterp) : TLSState(tlsInterp) {}

    virtual ~TLSShutdownState() {}

    TLSState *processSpecific(TLSRecordType_t tlsRecType) {
        TLSState *nextState = this;
        switch(tlsRecType) {
        case TLS_ALERT:
            if (getPayloadLen() > 2) {
                //We assume this is a Closure Alert, description = close_notify but it's encrypted
                closureAlertsCount_++;
                //We shouldn't see more than 2 close_notify
                if (closureAlertsCount_ > 1) {
                    throw TLSException(kExceptionClosureAlerts);
                }
            } else {
                closureErrorCount_++;
                if ((closureErrorCount_ + closureAlertsCount_) > 1) {
                    throw TLSException(kExceptionClosureError);
                }
            }
            break;
        default:
            closureErrorCount_++;
            if ((closureErrorCount_ + closureAlertsCount_) > 1) {
                throw TLSException(kExceptionClosureError);
            }
            break;
        }
        return nextState;
    }

private:
    uint8_t closureAlertsCount_{0};
    uint8_t closureErrorCount_{0};

};

#endif /* TLSSHUTDOWNSTATE_H_ */
