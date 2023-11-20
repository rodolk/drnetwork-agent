/*
 * ApplicationLog.h
 *
 *  Created on: Feb 24, 2022
 *      Author: rodolk
 */

#ifndef LOG_APPLICATIONLOG_H_
#define LOG_APPLICATIONLOG_H_

#include "daemonLog.h"

class ApplicationLog {
public:
    static void setLog(DaemonLog *log) {logPtr_ = log;}
    static DaemonLog& getLog() {return *logPtr_;}

private:
    static DaemonLog *logPtr_;
    ApplicationLog() {}
    virtual ~ApplicationLog() {}
};

#endif /* LOG_APPLICATIONLOG_H_ */
