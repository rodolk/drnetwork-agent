/*
 * TLSInterpreter.h
 *
 *  Created on: Apr 3, 2020
 *      Author: rodolk
 */

#ifndef TLSINTERPRETER_H_
#define TLSINTERPRETER_H_

#include <cstdint>
#include <vector>
#include <stdio.h>


#include "skb.h"
#include "TLSRecordType.h"
#include "TCPSegmentIterator.h"
#include "TLSState.h"
#include "TLSFirstState.h"
#include "daemonLog.h"

#define HELLO_REQUEST                 0x00
#define CLIENT_HELLO                  0x01
#define SERVER_HELLO                  0x02
#define CERTIFICATE                   0x0b
#define SERVER_KEY_EXCHANGE           0x0c
#define CERTIFICATE_REQUEST           0x0d
#define SERVER_DONE                   0x0e
#define CERTIFICATE_VERIFY            0x0f
#define CLIENT_KEY_EXCHANGE           0x10
#define FINISHED                      0x14

#define RECORD_PROTOCOL_HDR_LEN 5

/**
 * A TLSInterpreter belongs to an skb to which it also has a reference: skb_
 * This class is responsible for parsing, interpreting, and analyzing the TLS messages
 * between two end points using this skb locally.
 * TLSInterpreter has a TLS State machine to analyze the different TLS protocols (handshake, ChangeCipherSpec, ...).
 * It will parse the protocol and get relevant data using a TCPSegmentIterator (tcpSgmIter_).
 * It has the possibility of getting data, TCP Payload data, from the messages and stores the chunks of data in a vector:
 * msgPayloadVector_
 * checkTLS is a especial method that has to be called when the TCP connection sees the first TCP segment with Payload.
 *
 */
class TLSInterpreter {
public:
    const uint8_t kVersionMajor = 3;
    const uint8_t kVersionMinorMaxPlusOne = 4;
    static const int kAlertException = 1;
    static const int kTLSException = 2;
    bool handshakeDone{false};
    struct timeval tempTimestamp{0,0};

    struct dataChunk_t {
        const uint8_t *data;
        uint16_t len;
        dataChunk_t(const uint8_t *dp, uint16_t l) : data(dp), len(l) {}
    };

    TLSInterpreter(skb_t *skb) : skb_(skb), tcpSgmtIter_(*(new TCPSegmentIterator(skb)))  {
        skb_->tlsInterpreter = this;
        state_ = new TLSFirstState(this);
        msgPayloadVector_.clear();
    }
    TLSInterpreter(skb_t *skb, uint16_t tcpPayloadStart) : skb_(skb), tcpSgmtIter_(*(new TCPSegmentIterator(skb)))  {
        skb_->tlsInterpreter = this;
        skb_->firstTCPPayloadByte = tcpSgmtIter_.getOffsetLastSegment() + tcpPayloadStart;
        state_ = new TLSFirstState(this);
    }

    virtual ~TLSInterpreter();

    /**
     * Checks if the connection for the owner skb is TLS.
     * This method must be called as soon as the first TCP message with payload is received,
     * usually after TCP handshake.
     * This method doesn't return any value.
     * It will set isTLS to 1 in the owner skb, if it determines it's a TLS
     * connection.
     * After calling this function the caller must check for skb->isTLS
     * This method also initializes internal variables to parse TLS messages.
     *
     *
     */
    void checkTLS();

    /**
     * Process the TLS connection within the specifi state context
     *
     * @throws TLSAlertEXception
     * @throws TLSException
     */
    void process() {
        try {
            bool processAgain = true;
            while(processAgain) {
                TLSState *newState = state_->process(processAgain);
                while (newState != state_) {
                    delete state_;
                    state_ = newState;
                    newState = state_->init();
                }
            }
        } catch(TLSAlertException& excep) {
            alertState_ = true;
            alertCode_ = excep.getCode();
            alertSeverity_ = excep.getSeverity();
            throw TLSException(kAlertException);
        } catch(TLSException& excep) {
            alertState_ = true;
            alertCode_ = excep.getCode();
            alertSeverity_ = 0;
            throw TLSException(kTLSException);
        }
    }

    /**
     * Tells you whether the TLS connection is in Alert state
     *
     * @return  true or false
     */
    bool isAlertState() {return alertState_;}

    /**
     * Returns the alert code
     *
     * @return alert code
     */
    uint8_t getAlertCode() {return alertCode_;}
    /**
     * Returns the alert level when an Alert was detected
     *
     * @return alert level
     *          1- Warning
     *          2- Fatal
     */
    uint8_t getAlertSeverity() {return alertSeverity_;}

    void calcHShakeDoneLatency() {
        calcLatency(skb_, &tempTimestamp);
    }

private:
    skb_t *skb_;
    TCPSegmentIterator& tcpSgmtIter_;
    TLSState *state_{nullptr};
    uint16_t currRecordProtocolPloadLen_{0};
    uint16_t currRecordProtocolPloadReadSoFar__{0};
    uint8_t currRecordProtocolHdr[RECORD_PROTOCOL_HDR_LEN];
    uint16_t currRecordProtocolHdrLen_{RECORD_PROTOCOL_HDR_LEN};
    uint16_t currRecordProtocolHdrReadSoFar_{0};
    TLSRecordType_t currHLProtocolMsg_{TLS_NONE};
    //uint8_t *currTLSMsg_{nullptr};
    //uint32_t currTLSBufferSize_{0};
    bool alertState_{false};
    uint8_t alertCode_{0};
    uint8_t alertSeverity_{0};
    bool readingNextRPHdr_{false};
    std::vector<dataChunk_t> msgPayloadVector_;

    uint8_t readRecordProtocolHdr();
    uint8_t readCompleteCurrHLProtocolMsg(bool readData);

    friend class TLSState;
};

#endif /* TLSINTERPRETER_H_ */
