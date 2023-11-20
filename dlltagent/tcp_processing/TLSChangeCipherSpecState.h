/*
 * TLSChangeCipherSpecState.h
 *
 *  Created on: Apr 13, 2020
 *      Author: rodolk
 */

#ifndef TLSCHANGECIPHERSPECSTATE_H_
#define TLSCHANGECIPHERSPECSTATE_H_

#include "TLSState.h"

class TLSChangeCipherSpecState: public TLSState {
public:
    TLSChangeCipherSpecState(TLSInterpreter *tlsInterp) : TLSState(tlsInterp) {}
    virtual ~TLSChangeCipherSpecState();
    virtual TLSState *processSpecific(TLSRecordType_t tlsRecType) {
        return this;
    }

};

#endif /* TLSCHANGECIPHERSPECSTATE_H_ */
