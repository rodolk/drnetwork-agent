/*
 * TLSState.h
 *
 *  Created on: Apr 6, 2020
 *      Author: rodolk
 */

#ifndef TLSSTATE_H_
#define TLSSTATE_H_

#include <exception>
#include <sstream>

#include "State.h"
#include "TLSRecordType.h"
#include "daemonLog.h"

class TLSInterpreter;

class TLSException : public std::exception {
public:
    TLSException(uint8_t code) : code_(code) {}
    virtual const char* what() const throw() {
        std::stringstream sstr;
        sstr << "TLS Alert: " << (unsigned int) code_;
        return sstr.str().c_str();
    }
    uint8_t getCode() {return code_;}
protected:
    uint8_t code_;
};

class TLSAlertException : public TLSException {
public:
    TLSAlertException(uint8_t code, uint8_t severity) : TLSException(code), severity_(severity) {}
    virtual const char* what() const throw() {
        std::stringstream sstr;
        sstr << "TLS Alert - Code: " << (unsigned int) code_ << " - Severity: " << severity_;
        return sstr.str().c_str();
    }
    uint8_t getSeverity() {return severity_;}
private:
    uint8_t severity_;
};

/**
 * This class is a TLS State in the TLS State Machine from which all TLS states inherit
 * It works as a template method and the main method is process.
 *
 */
class TLSState: public State {
public:
    static const int kExceptionClosureAlerts     = 10;
    static const int kExceptionClosureError      = 11;
    static const int kExceptionUnexpectedMessage = 12;

    TLSState(TLSInterpreter *tlsInterp): tlsInterp_(tlsInterp) {}

    virtual ~TLSState();

    /**
     * This is the general process method for almost all TLSState classes
     * The main task is to read TLS header and TLS payload.
     *
     * @param processAgain this is an out parameter, it will indicate if the caller needs to call process again or there is no
     *        more data to read and it needs to wait auntil new data arrives.
     *
     * @return TLSState for the State Machine.
     */
    virtual TLSState *process(bool& processAgain);

    /**
     * This method must be called for a state that is beginning to be used after
     * a state transition
     *
     * @return TLSState is the state to which the State Machine needs to transition, or stay if the same.
     *
     */
    virtual TLSState *init() {
        return this;
    }

protected:
    TLSInterpreter *tlsInterp_;

    TLSRecordType_t getcurrHLMsgType();

    /**
     * If TLS header needs to be read
     *
     * @param state true if it needs to be read
     */
    void setReadingNextRPHdr(bool state);

    /**
     * Prepare Bytes from kept data to be read with getBytes later
     *
     * @param numBytes amount of Bytes required
     *
     * @return true is the amount of Bytes requested is available
     */
    bool prepareBytes(uint16_t numBytes);

    /**
     * get Bytes for index idx of tlsInterp_->msgPayloadVector_
     *
     * @param idx       index of tlsInterp_->msgPayloadVector_ to be read.
     * @param numBytes  out parameter with amount of data returned.
     *
     * @return  pointer to data (numBytes of data)
     */
    const uint8_t *getBytes(uint8_t idx, uint16_t &numBytes);

    /**
     * Any specific process that may need to be done depending on the sate
     *
     * @param   TLSRecordType_t record type of a TLS header
     * @return  TLSState to stay in or transition to
     *
     */
    virtual TLSState *processSpecific(TLSRecordType_t) = 0;

    /**
     * Method to imlement if any process needs to be done for a payload in a specific state
     *
     */
    virtual void processPayload() {}

    /**
     * If the state requires the payload data to be kept for further processing.
     *
     * @return true if needs to keep the data.
     */
    virtual bool requiresDataRead() const {return false;}

    /**
     * Return the length of current TLS packet's payload
     *
     * @return payload length
     *
     */
    uint16_t getPayloadLen();

    uint16_t getSrcPort();
    uint16_t getDstPort();

};

#endif /* TLSSTATE_H_ */
