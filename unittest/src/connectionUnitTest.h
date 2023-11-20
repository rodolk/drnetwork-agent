/*
 * connectionUnitTest.h
 *
 *  Created on: Jul 8, 2021
 *      Author: rodolk
 */

#ifndef CONNECTIONUNITTEST_H_
#define CONNECTIONUNITTEST_H_

#include <cstdint>
namespace connectionUnitTest {


void executeStaleConnectionTests(uint16_t& testCounter);
void executeRefusedConnectionTests(uint16_t& testCounter);
void executeManyConnectionsTests(uint16_t& testCounter);
void executeTLSCloseNotifyTests(uint16_t& testCounter);


} //namespace connectionUnitTest


#endif /* CONNECTIONUNITTEST_H_ */
