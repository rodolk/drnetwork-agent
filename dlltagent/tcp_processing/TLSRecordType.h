/*
 * TLSRecordType.h
 *
 *  Created on: Apr 13, 2020
 *      Author: rodolk
 */

#ifndef TLSRECORDTYPE_H_
#define TLSRECORDTYPE_H_

enum TLSRecordType_t {TLS_NONE=0, TLS_CHANGE_CIPHER_SPEC=0x14, TLS_ALERT, TLS_HANDSHAKE, TLS_APPLICATION_DATA};

#endif /* TLSRECORDTYPE_H_ */
