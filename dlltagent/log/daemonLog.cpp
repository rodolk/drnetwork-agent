#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>

#include "daemonLog.h"

int DaemonLog::initialize(const char *logsDirectory, const char *_logFileName)
{
    int err = 0;
    
    if (initialized) return 0;
    
    pthread_mutex_lock(&logMutex);

    pErrorFile = fopen(errorFileName, "w");
    
    if (pErrorFile != NULL) {
        err = fputs("ERROR LOG FILE\n", pErrorFile);
        if (err >= 0) {
            if (strlen(_logFileName) > (LOG_FILENAME_LEN - EXTENSION_DATE_LEN)) {
                sprintf(errmsg, "ERROR: log filename greater than MAX: %u - Truncating\n", (unsigned int)strlen(_logFileName));
                err = fputs(errmsg, pErrorFile);
                if (err >= 0) {
                    strncpy(logfilename, _logFileName, (LOG_FILENAME_LEN - EXTENSION_DATE_LEN));
                }
            }
            else {
                strcpy(logfilename, _logFileName);
            }
            
            if (err >= 0) {
                sprintf(errmsg, "LOG File Name prefix: %s\n", logfilename);
                err = fputs(errmsg, pErrorFile);
                strcpy(errmsg, getNowTimeAsString().c_str());
                err = fputs(errmsg, pErrorFile);
                if (err >= 0)
                {
                    logFileManager_ = new LogFileManager(NUM_LINES_PER_LOGFILE, logfilename, logsDirectory);
                    if (logFileManager_->init()) {
                        sprintf(errmsg, "LOG File Opened: %s\n", logFileManager_->getCurrFilename().c_str());
                        err = fputs(errmsg, pErrorFile);
                    }
                    else
                    {
                        sprintf(errmsg, "ERROR: opening LOG File Name: %s\n", logFileManager_->getCurrFilename().c_str());
                        fputs(errmsg, pErrorFile);
                        err = -11;
                    }
                }
            }
        }
        if (err >= 0)
        {
            initialized = true;
        }
        
        fflush(pErrorFile);
    }
    else
    {
        fprintf(stderr, "Error opening startup log file: %s\n", errorFileName);
        err = -10;
    }

    pthread_mutex_unlock(&logMutex);
    
    return err;
}
