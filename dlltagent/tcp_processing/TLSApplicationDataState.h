/*
 * TLSApplicationDataState.h
 *
 *  Created on: Apr 13, 2020
 *      Author: rodolk
 */

#ifndef TLSAPPLICATIONDATASTATE_H_
#define TLSAPPLICATIONDATASTATE_H_

#include "TLSState.h"

class TLSApplicationDataState: public TLSState {
public:
    TLSApplicationDataState(TLSInterpreter *tlsInterp) : TLSState(tlsInterp) {}
    virtual ~TLSApplicationDataState();

    virtual TLSState *processSpecific(TLSRecordType_t tlsRecType);
};

#endif /* TLSAPPLICATIONDATASTATE_H_ */
