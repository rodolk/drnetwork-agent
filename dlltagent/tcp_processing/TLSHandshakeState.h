/*
 * TLSHandshakeState.h
 *
 *  Created on: Apr 6, 2020
 *      Author: rodolk
 */

#ifndef TLSHANDSHAKESTATE_H_
#define TLSHANDSHAKESTATE_H_

#include "TLSState.h"

class TLSHandshakeState: public TLSState {
public:
    TLSHandshakeState(TLSInterpreter *tlsInterp) : TLSState(tlsInterp) {}
    virtual ~TLSHandshakeState();

    virtual TLSState *processSpecific(TLSRecordType_t tlsRecType);
private:

};

#endif /* TLSHANDSHAKESTATE_H_ */
