/*
 * processIdentifier.cpp
 *
 *  Created on: Apr 15, 2021
 *      Author: rodolk
 */

#include "processIdentifier.h"

#include <string>
#include <sstream>
#include <iostream>
#include <chrono>
#include <map>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "applicationLog.h"


using namespace std;



ProcessIdentifier::ProcessIdentifier() {
    systemOutputLine1_ = (char *)malloc(SYSTEM_OUTPUT_LINE_VALUE);
    systemOutputLine2_ = (char *)malloc(SYSTEM_OUTPUT_LINE_VALUE);
}

ProcessIdentifier::~ProcessIdentifier() {
    free(systemOutputLine1_);
    free(systemOutputLine2_);
}


int ProcessIdentifier::initializeSpecific() {
    if (!netstatExists_) {
        ApplicationLog::getLog().warning("netstat not available. I will not be able to obtain data for a process using a port\n");
        return -1;
    }
    return 0;
}

uint32_t ProcessIdentifier::get_line(char **buffer, uint32_t *len, FILE *fp) {
    uint32_t bufLen = *len;
    uint32_t readLen = 0;
    char *bufPtr = *buffer;
    char *res = fgets(bufPtr, bufLen, fp);
    if (res != NULL) {
        readLen = strlen(bufPtr);
        while(res != NULL && bufPtr[readLen - 1] != '\n') {
            bufLen += SYSTEM_OUTPUT_LINE_VALUE;
            bufPtr = (char *)realloc(bufPtr, bufLen);
            res = fgets(bufPtr + readLen, SYSTEM_OUTPUT_LINE_VALUE + 1, fp);
            if (res != NULL) {
                readLen += strlen(bufPtr  + readLen);
            } else {
                if (ferror(fp) != 0) {
                    ApplicationLog::getLog().error("ERROR reading pipe!\n");
                }
            }
        }
    } else {
        if (ferror(fp) != 0) {
            ApplicationLog::getLog().error("ERROR reading pipe!\n");
        }
    }
    *buffer = bufPtr;
    *len = bufLen;

    return readLen;
}


#define PS_CMD_LEN 60

bool ProcessIdentifier::getProcessCmd(const char *pid, int32_t *ppid, uint32_t *uid) {
    FILE *fp;
    static char command[PS_CMD_LEN + 1];
    sprintf(command, "ps -p %s -o ppid,uid,args --no-headers", pid);

    /* Open the command for reading. */
    fp = popen(command, "r");
    if (fp == NULL) {
        ApplicationLog::getLog().error("Failed to run command: %s\n", command);
        exit(1);
    }

    uint32_t lenRead = get_line(&systemOutputLine1_, &sysOutLineLen_, fp);
    pclose(fp);
    if (lenRead > 0) {
        const char *beginData;
        char *ptr = systemOutputLine1_;
        char *ptrStrtol;
        while(*ptr == ' ') ptr++;
        beginData = ptr;
        while(*ptr != ' ') ptr++;
        *ptr = 0;
        long value = strtol(beginData, &ptrStrtol, 10);
        if (*ptrStrtol != 0) {
            ApplicationLog::getLog().error("Failed to convert PPID %s\n", beginData);
            *ppid = -1;
        } else {
            *ppid = (int32_t)value;
        }
        ptr++;
        while(*ptr == ' ') ptr++;
        beginData = ptr;
        while(*ptr != ' ') ptr++;
        *ptr = 0;
        value = strtol(beginData, &ptrStrtol, 10);
        if (*ptrStrtol != 0) {
            ApplicationLog::getLog().error("Failed to convert UID %s\n", beginData);
            *uid = 0xFFFFFFFF;
        } else {
            *uid = (int32_t)value;
        }
        ptr++;
        while(*ptr == ' ') ptr++;
        beginData = ptr;
        systemOutputLine1_[lenRead - 1] = 0;
        strcpy(systemOutputLine2_, systemOutputLine1_);
        return true;
    } else {
        strcpy(systemOutputLine2_, "NA");
    }
    return false;
}

void ProcessIdentifier::identifyAllProcesses() {
    const char *cmd = "netstat -natp | grep -P \'\\d+\\.\\d+\\.\\d+\\.\\d+\\:\\d+\'";
    identifyProcessesWithCmd(cmd);
}


void ProcessIdentifier::identifyProcessForPort(uint32_t localIPAddr, const char *localIP, uint16_t localPort) {
    if (netstatExists_) {
        char cmd[200];
        sprintf(cmd, "netstat -natp | grep %s | grep %u", localIP, localPort);

//    identifyProcessWithCmd(cmd, localIPAddr, localPort);
        identifyProcessesWithCmd(cmd);
    }
}

int ProcessIdentifier::initializeCmd() {
    FILE *fp;
    char outputLine[1035];
    char *olAddressPtr;
    char *olPIDPtr;
    const char *cmd = "netstat -natp";
    int ret = 0;

    /* Open the command for reading. */
    fp = popen(cmd, "r");
    if (fp == NULL) {
        ApplicationLog::getLog().error("Failed to run popen\n");
        return -1;
    }

    /* Read the output a line at a time - output it. */
    while (fgets(outputLine, sizeof(outputLine), fp) != NULL) {
        if (strncmp(outputLine, "Proto", 5) == 0) {
            netstatExists_ = true;
            break;
        }
        if (strstr(outputLine, "not found")) {
            break;
        }
    }

    if (netstatExists_) {
        olAddressPtr = strstr(outputLine, "Local Address");
        olPIDPtr = strstr(outputLine, "PID/Program name");
        if (olAddressPtr != NULL && olPIDPtr != NULL) {
            spaceLocalAddress_ = olAddressPtr - outputLine;
            spacePID_ = olPIDPtr - outputLine;
            while (fgets(outputLine, sizeof(outputLine), fp) != NULL) {
                populateNextProcess(outputLine, spaceLocalAddress_, spacePID_);
            }
        } else {
            netstatExists_ = false;
            ApplicationLog::getLog().warning("Different format for netstat. I will not be able to populate process data with netstat\n");
            ret = -3;
        }
    } else {
        ApplicationLog::getLog().warning("netstat was not found in this system cannot populate process data at the beginning\n");
        ApplicationLog::getLog().warning("For better information about processes using the network you can install package net-tools and have netstat command available\n");
        ret = -2;
    }

    pclose(fp);
    return ret;
}

#define SHORT_NAME_LEN 60

void ProcessIdentifier::identifyProcessesWithCmd(const char *cmd) {
    FILE *fp;
    char outputLine[1035];

    fp = popen(cmd, "r");
    if (fp == NULL) {
        ApplicationLog::getLog().error("Failed to run command: %s\n", cmd);
        exit(1);
    }

    while (fgets(outputLine, sizeof(outputLine), fp) != NULL) {
        populateNextProcess(outputLine, spaceLocalAddress_, spacePID_);
    }

    pclose(fp);
}

void ProcessIdentifier::setPortData(uint32_t localIPAddr, uint16_t localPort, int32_t pid) {
    listenPIDMutex_.lock();
    listenIPPortPidMap_[localIPAddr][localPort].pid = pid;
    listenIPPortPidMap_[localIPAddr][localPort].lastTime = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    listenPIDMutex_.unlock();
}


void ProcessIdentifier::populateNextProcess(const char *outputLine, uint32_t spaceLocalAddress, uint32_t spacePID) {
    char ipAddr[80];
    char port[10];
    char pidStr[10];
    int32_t pid;
    char shortName[30];
    struct in_addr ipAddrInAddr;
    uint16_t portInt;

    //printf("ACA-5, %s\n", outputLine);
    ipAddr[0] = 0;
    port[0] = 0;
    pidStr[0] = 0;
    shortName[0] = 0;
    const char *ipBegin = outputLine + spaceLocalAddress;
    if (ipBegin[3] == '.' || ipBegin[2] == '.' || ipBegin[1] == '.') {
        const char *endIP = strchr(outputLine + spaceLocalAddress, ':');
        if (endIP) {
            memcpy(ipAddr, outputLine + spaceLocalAddress, (endIP - (outputLine + spaceLocalAddress)));
            ipAddr[(endIP - (outputLine + spaceLocalAddress))] = 0;
            endIP++;
            const char *endPort = strchr(endIP, ' ');
            if (endPort) {
                memcpy(port, endIP, endPort - endIP);
                port[endPort - endIP] = 0;
                const char *endPID = strchr(outputLine + spacePID, '/');
                if (endPID != NULL) {
                    memcpy(pidStr, outputLine + spacePID, (endPID - (outputLine + spacePID)));
                    pidStr[(endPID - (outputLine + spacePID))] = 0;
                    //printf("ACA-6, %s\n", pid);
                    endPID++;
                    const char *endShortName = strchr(endPID, ' ');
                    if (endShortName) {
                        memcpy(shortName, endPID, endShortName - endPID);
                        shortName[endShortName - endPID] = 0;
                        //printf("ACA-7, %s\n", shortName);
                    }
                }
            }
        }
        //printf("IP addr: %s - Port: %s - PID: %s - Short Name: %s\n", ipAddr, port, pid, shortName);
        inet_pton(AF_INET, ipAddr, &ipAddrInAddr);
        portInt = std::stoul(port);
        if (pidStr[0] != 0) {
            char *ptrStrtol;
            long value = strtol(pidStr, &ptrStrtol, 10);
            if (*ptrStrtol != 0) {
                ApplicationLog::getLog().error("Failed to convert PID %s\n", pidStr);
                pid = -1;
            } else {
                pid = (int32_t)value;
            }

            populateProcess(pid, pidStr, shortName);
            setPortData((uint32_t)ipAddrInAddr.s_addr, portInt, pid);
        } else {
            if (port[0] != 0) {
                //setPortData((uint32_t)ipAddrInAddr.s_addr, portInt, "", "", "");
            }
        }
    }
}
