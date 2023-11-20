/*
 * TLSAlertState.h
 *
 *  Created on: Apr 13, 2020
 *      Author: rodolk
 */

#ifndef TLSALERTSTATE_H_
#define TLSALERTSTATE_H_

#include <iostream>
#include "TLSState.h"
#include "TLSShutdownState.h"

class TLSAlertState: public TLSState {
public:
    static const uint16_t kNumBytesinAlertMsg = 2;
    TLSAlertState(TLSInterpreter *tlsInterp) : TLSState(tlsInterp) {}
    TLSAlertState(TLSInterpreter *tlsInterp, bool fromApplicationState) : TLSState(tlsInterp), fromApplicationState_(fromApplicationState) {}

    virtual TLSState *init() {
        //If this method is executed this is because we didn't throw a TLSAlertException in processPayload before
        //Then this is was a closure alert. We need to pass to TLSShutdownState.
        if (fromApplicationState_) {
            return new TLSShutdownState(tlsInterp_);
        }
        return this;
    }

    virtual ~TLSAlertState();

protected:
    virtual TLSState *processSpecific(TLSRecordType_t tlsRecType) {
        return this;
    }

    /**
     * Will process alert code and alert level from an Alert TLS message.
     * If alert description (second Byte) is not a closure alert (0, but encrypted ...) it throws a TLSAlertException
     * Alert description 0 is a closure alert, indicating close notify from one side to other because of call to
     * SSL_Shutdown during an orderly SSL close connection.
     * We don't check severity in the closure alert because we don't know if everybody sets it to 0 or to a warning.
     *
     */
    virtual void processPayload() {
        if (prepareBytes(kNumBytesinAlertMsg)) {
            uint16_t numBytes = kNumBytesinAlertMsg;
            uint8_t idx = 0;
            const uint8_t *data = getBytes(idx, numBytes);
            severity_ = data[0];
            if (kNumBytesinAlertMsg > numBytes) {
                idx++;
                numBytes = 1;
                data = getBytes(idx, numBytes);
                code_ = data[0];
            } else {
                code_ = data[1];
            }
            if (!fromApplicationState_) {
                if (getPayloadLen() == 2) {
                    throw TLSAlertException(code_, severity_);
                } else {
                    //We assume CLOSE NOTIFY before Application Data State and throw exception
                    throw TLSAlertException(0, 1);
                }
            } else {
                //TODO: If we come from TLSApplicationDataState and length > 2
                //We assume Closure Alert, description = close_notify (but encrypted)
                //Because it's an encrypted alert and we cannot decrypt at this moment
                //If length is 2 we consider it is another alert.
                //Caution :If this is a different Alert or there is a close notify with length 0, we are having an error
                //For closure alert we're not throwing TLSAlertException.
                if (getPayloadLen() == 2) {
                    throw TLSAlertException(code_, severity_);
                } else {
                    return;
                }
            }
        }
    }

    virtual bool requiresDataRead() const {return true;}

private:
    uint8_t code_{0};
    uint8_t severity_{0};
    bool fromApplicationState_{false};
    uint8_t closureAlertsCount_{0};

};

#endif /* TLSALERTSTATE_H_ */
