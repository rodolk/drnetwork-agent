#include <stdio.h>
#include <stdarg.h>



#include "daemonLog.h"

extern "C" {


#include "daemon_log.h"

DaemonLog *logObject = nullptr;
bool initialized = false;

int initializeWithFile(const char *initialLogFile, const char *directory, const char *_logFileName, unsigned int logLevel) {
    if (!initialized) {
        initialized = true;
        logObject = new DaemonLog(initialLogFile);
        logObject->initialize(directory, _logFileName);
        logObject->setLogLevel((DaemonLog::eLOGLevel) logLevel);
    }
    return 0;
}

int initialize(const char *initialLogFile) {
    if (!initialized) {
        initialized = true;
        logObject = new DaemonLog(initialLogFile);
        logObject->initialize();
        logObject->setLogLevel(DaemonLog::LOGLevelDebug);
    }
    return 0;
}


int logerror(const char *format, ...) {
    int res = 0;
    va_list args;

    if (initialized) {
        va_start(args, format);
        res = logObject->error(format, args);
        va_end (args);
    }

    return res;
}

int logwarning(const char *format, ...) {
    int res = 0;
    va_list args;

    if (initialized) {
        va_start(args, format);
        res = logObject->warning(format, args);
        va_end (args);
    }

    return res;
}

int loginfo(const char *format, ...) {
    int res = 0;
    va_list args;

    if (initialized) {
        va_start(args, format);
        res = logObject->info(format, args);
        va_end (args);
    }

    return res;
}

int loginfov(const char *format, ...) {
    int res = 0;
    va_list args;

    if (initialized) {
        va_start(args, format);
        res = logObject->infov(format, args);
        va_end (args);
    }

    return res;
}

int logdebug(const char *format, ...) {
    int res = 0;
    va_list args;

    if (initialized) {
        va_start(args, format);
        res = logObject->debug(format, args);
        va_end (args);
    }

    return res;
}

}
