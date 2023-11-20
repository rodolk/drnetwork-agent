/*
 * processIdentifierLSOF.h
 *
 *  Created on: Apr 15, 2021
 *      Author: rodolk
 */

#ifndef PROCESSIDENTIFIER_LSOF_H_
#define PROCESSIDENTIFIER_LSOF_H_

#include <stdint.h>

#include "processIdentifier.h"

class ProcessIdentifierLSOF : public ProcessIdentifier {
public:
    ProcessIdentifierLSOF() {}
    virtual ~ProcessIdentifierLSOF() {}

private:
    bool lsofExists_{true};
    std::mutex cmdMutex_;

    void identifyProcessForPort(uint32_t localIPAddr, const char *localIP, uint16_t localPort);
    int identifyProcessWithCmd(const char *cmd, const char *cmd2, uint32_t localIPAddr, const char *localIPStr, uint16_t localPort);
    int readNextProcess(char *line, size_t buffLen, FILE *fp, char *pid, char *shortName, char *ppid, char *uid);
    int getField(char *line, const size_t buffLen, FILE *fp, char *field, uint32_t maxLen);
    int initializeSpecific();

};

#endif /* PROCESSIDENTIFIER_LSOF_H_ */
