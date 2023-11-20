/*
 * processIdentifier.cpp
 *
 *  Created on: Apr 15, 2021
 *      Author: rodolk
 */

#include "processIdentifierLSOF.h"

#include <stdio.h>
#include <string.h>

#include "applicationLog.h"

#define SHORT_NAME_LEN 60
#define FIELD_LEN 10

using namespace std;

int ProcessIdentifierLSOF::initializeSpecific() {
    FILE *fp;
    char outputLine[1035];

    fp = popen("lsof -v 2>&1", "r");
    if (fp == NULL) {
        ApplicationLog::getLog().error("Failed to run popen\n");
        return -1;
    }

    if (fgets(outputLine, sizeof(outputLine), fp) != NULL) {
        if (outputLine[0] == 0) {
            fgets(outputLine, sizeof(outputLine), fp);
            if (strstr(outputLine, "not found") != NULL) {
                lsofExists_ = false;
            }
        } else {
            if (strstr(outputLine, "not found") != NULL) {
                lsofExists_ = false;
            }
        }
    }

    pclose(fp);

    if (!lsofExists_) {
        ApplicationLog::getLog().warning("lsof command not found. I will not be able to find process data with lsof.\n");
        ApplicationLog::getLog().warning("You can install lsof package for more efficient identification of a process using a port.\n");
        return -2;
    }

    return 0;
}



void ProcessIdentifierLSOF::identifyProcessForPort(uint32_t localIPAddr, const char *localIP, uint16_t localPort) {
    char cmd[200];
    char cmd2[200];
    sprintf(cmd, "lsof -FpcRu -iTCP@%s:%u -Pn", localIP, localPort);
    sprintf(cmd2, "lsof -FpcRu -iTCP:%u -Pn", localPort);

    if (lsofExists_) {
        identifyProcessWithCmd(cmd, cmd2, localIPAddr, localIP, localPort);
    }
}
//lsof -FpcRun -iTCP:443 -sTCP:LISTEN -P -n
//lsof -FpcRun -iTCP@139.59.130.207:443 -sTCP:LISTEN -P -n



int ProcessIdentifierLSOF::getField(char *line, const size_t buffLen, FILE *fp, char *field, uint32_t maxLen) {
    char *ptr;
    uint32_t i;
    field[0] = 0;
    if (fgets(line, buffLen, fp) != NULL) {
        ptr = &line[1];
        i = 0;
        while(*ptr != '\n' && i < maxLen) {
            field[i] = *ptr;
            i++;
            ptr++;
        }
        field[i] = 0;
        return 0;
    } else {
        ApplicationLog::getLog().debug("getField from lsof could not find a line\n");
        return -1;
    }
}

int ProcessIdentifierLSOF::readNextProcess(char *line,
        const size_t buffLen,
        FILE *fp,
        char *pid,
        char *shortName,
        char *ppid,
        char *uid) {
    pid[0] = 0;
    shortName[0] = 0;
    ppid[0] = 0;
    uid[0] = 0;

    int ret = getField(line, buffLen, fp, pid, FIELD_LEN);
    if (ret == -1) return -1;
    if (pid[0] == 0) return -2;

    getField(line, buffLen, fp, ppid, FIELD_LEN);
    getField(line, buffLen, fp, shortName, SHORT_NAME_LEN);
    getField(line, buffLen, fp, uid, FIELD_LEN);
    return 0;
}

int ProcessIdentifierLSOF::identifyProcessWithCmd(const char *cmd, const char *cmd2, uint32_t localIPAddr, const char *localIPStr, uint16_t localPort) {
    FILE *fp;
    char outputLine[1035];
    char pidStr[FIELD_LEN];
    char ppidStr[FIELD_LEN];
    char uidStr[FIELD_LEN];
    char shortName[SHORT_NAME_LEN + 1];
    int retVal;

    std::unique_lock<mutex> lock(cmdMutex_);
    fp = popen(cmd, "r");
    if (fp == NULL) {
        ApplicationLog::getLog().error("Failed to executed popen\n");
        return -1;
    }

    retVal = readNextProcess(outputLine, sizeof(outputLine), fp, pidStr, shortName, ppidStr, uidStr);
    pclose(fp);
    if (retVal == -1) {
        fp = popen(cmd2, "r");
        if (fp == NULL) {
            ApplicationLog::getLog().error("Failed to executed popen\n");
            return -1;
        }

        retVal = readNextProcess(outputLine, sizeof(outputLine), fp, pidStr, shortName, ppidStr, uidStr);
        pclose(fp);
        if (retVal == -1) {
            ApplicationLog::getLog().infov("Detected SYN to IP %s, port: %u and no process is listening in this port.\n", localIPStr, localPort);
            return -1;
        }
    }

    if (pidStr[0] != 0) {
        int32_t pid;
        int32_t ppid;
        uint32_t uid;
        char *ptr;

        long value = strtol(pidStr, &ptr, 10);
        if (*ptr != 0) {
            ApplicationLog::getLog().error("Failed to convert PID %s for IP %s, port: %u\n", pidStr, localIPStr, localPort);
            return -1;
        }
        pid = (int32_t)value;

        value = strtol(ppidStr, &ptr, 10);
        if (*ptr != 0) {
            ApplicationLog::getLog().error("Failed to convert PPID %s for IP %s, port: %u\n", ppidStr, localIPStr, localPort);
            ppid = -1;
        } else {
            ppid = (int32_t)value;
        }

        value = strtol(uidStr, &ptr, 10);
        if (*ptr != 0) {
            ApplicationLog::getLog().error("Failed to convert UID %s for IP %s, port: %u\n", uidStr, localIPStr, localPort);
            uid = 0xFFFFFFFF;
        } else {
            uid = (uint32_t)value;
        }

        setProcessData(pid, ppid, uid, shortName);
        setPortData(localIPAddr, localPort, pid);
        return 0;
    } else {
        ApplicationLog::getLog().error("Couldn't obtain PID for IP %s, port: %u\n", localIPStr, localPort);
        setPortData(localIPAddr, localPort, -2);
        return -1;
    }
}
