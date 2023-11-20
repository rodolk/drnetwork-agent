#ifndef DAEMON_LOG_H_
#define DAEMON_LOG_H_

#include <ctime>

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>

#include "timeHelper.h"
#include "logFileManager.h"
//#include "Configuration.h"

#define LOG_FILENAME_LEN 1024
#define ERR_MSG_LEN 1280
#define LOG_STR_HALF_LEN 1024
#define LOG_STR_LEN 2048
#define EXTENSION_DATE_LEN 20
#define ERROR_FILE_NAME "error.log"
#define NUM_LINES_PER_LOGFILE 50000

#define INIT_YEAR 1900
#define INIT_MONTH 1


class DaemonLog
{
    LogFileManager *logFileManager_{nullptr};
    FILE *pErrorFile{nullptr};
    char errorFileName[200];
    char logfilename[LOG_FILENAME_LEN + 1];
    char errmsg[ERR_MSG_LEN + 1];
    bool initialized;
    
    bool errorEnabled;
    bool warningEnabled;
    bool informationEnabled;
    bool informationVerboseEnabled;
    bool debugEnabled;
    
    char logstr[LOG_STR_LEN + 1];
    
    pthread_mutex_t logMutex;
    
    int completeFilename(char *filename) {
        int len;
        
        strcat(filename, "_");
        
        len = strlen(filename);
        
        sprintf(filename + len, "%s.log", getNowTimeAsString().c_str());
        
        return strlen(filename);
    }


    int log(const char *logType, const char *format, va_list args) {
        int res;
        int len = strlen(logType);

        pthread_mutex_lock(&logMutex);
        
        memcpy(logstr, logType, len);
        memcpy(logstr + len, "::", 2);
        
        len += 2;
        
        sprintf(logstr + len, "%s ::", getNowAsLogFormat());
        len  = strlen(logstr);
        
        res = vsnprintf(logstr + len, LOG_STR_LEN - (len), format, args);
        
        if (res >= 0) {
            if (nullptr != logFileManager_) {
                logFileManager_->processRotation();
                ofstream& logsFile = logFileManager_->getFileStream();

                logsFile << logstr;
                
                logFileManager_->incLine();

                if (logsFile.bad()) {
                    res = -0xFFFF;
                }
            } else {
                fprintf(stdout, "%s\n", logstr);
            }
        }
        
        if (nullptr != logFileManager_) {
            logFileManager_->flush();
        }
        pthread_mutex_unlock(&logMutex);
        
        return res;
    }
    
  public:
    typedef enum {LOGLevelError = 0, LOGLevelWarning, LOGLevelInfo, LOGLevelInfoVerbose, LOGLevelDebug} eLOGLevel;
    
    DaemonLog(const char *errorFileNameLog = nullptr)
    {
        pthread_mutex_init(&logMutex, NULL);
        if (errorFileNameLog == nullptr)
            sprintf(errorFileName, "%s", ERROR_FILE_NAME);
        else
            sprintf(errorFileName, "%s", errorFileNameLog);

        initialized = false;
    
        errorEnabled       = false;
        warningEnabled     = false;
        informationEnabled = false;
        informationVerboseEnabled = false;
        debugEnabled       = false;
    }
    
    ~DaemonLog()
    {
        if (nullptr != logFileManager_)
        {
            fclose(pErrorFile);
            delete logFileManager_;
        }
    }
    
    int initialize(const char *logsDirectory, const char *_logFileName);
    int initialize()
    {
        initialized = true;
        pErrorFile = NULL;
        return 0;
    }
    
    void enableError()
    {
        errorEnabled = true;
    }
    
    void disableError()
    {
        errorEnabled = false;
    }
    
    void enableDebug()
    {
        debugEnabled = true;
    }
    
    void disableDebug()
    {
        debugEnabled = false;
    }
    
    void enableInfo()
    {
        informationEnabled = true;
    }
    
    void disableInfo()
    {
        informationEnabled = false;
    }
    
    void enableInfoVerbose()
    {
        informationVerboseEnabled = true;
    }
    
    void disableInfoVerbose()
    {
        informationVerboseEnabled = false;
    }
    
    void enableWarning()
    {
        warningEnabled = true;
    }
    
    void disableWarning()
    {
        warningEnabled = false;
    }

    
    public:
    void setLogLevel(eLOGLevel logLevel)
    {
        if (logLevel >= LOGLevelError)
        {
            enableError();
        }
        else
        {
            disableError();
        }
        
        if (logLevel >= LOGLevelWarning)
        {
            enableWarning();
        }
        else
        {
            disableWarning();
        }
        
        if (logLevel >= LOGLevelInfo)
        {
            enableInfo();
        }
        else
        {
            disableInfo();
        }
        
        if (logLevel >= LOGLevelInfoVerbose)
        {
            enableInfoVerbose();
        }
        else
        {
            disableInfoVerbose();
        }
        
        if (logLevel >= LOGLevelDebug)
        {
            enableDebug();
        }
        else
        {
            disableDebug();
        }
    }
    
    bool isDebugEnabled() {return debugEnabled;}
    bool isInfoEnabled() {return informationEnabled;}
    bool isWarningEnabled() {return warningEnabled;}

    int error(const char *format, ...)
    {
        int res;
        va_list args;
        
        if (!initialized) return 0;
        if (!errorEnabled) return 0;
        
        va_start(args, format);
        res = log("ERROR", format, args);
        va_end (args);
        
        return res;
    }

    int warning(const char *format, ...)
    {
        int res;
        va_list args;
        
        if (!initialized) return 0;
        if (!warningEnabled) return 0;
        
        va_start(args, format);
        res = log("WARNING", format, args);
        va_end (args);
        
        return res;
    }
    
    int info(const char *format, ...)
    {
        int res;
        va_list args;
        
        if (!initialized) return 0;
        if (!informationEnabled) return 0;
        
        va_start(args, format);
        res = log("INFO", format, args);
        va_end (args);
        
        return res;
    }
        
    int infov(const char *format, ...)
    {
        int res;
        va_list args;
        
        if (!initialized) return 0;
        if (!informationVerboseEnabled) return 0;
        
        va_start(args, format);
        res = log("INFO", format, args);
        va_end (args);
        
        return res;
    }
        
    int debug(const char *format, ...)
    {
        int res;
        va_list args;
        
        if (!initialized) return 0;
        if (!debugEnabled) return 0;
        
        va_start(args, format);
        res = log("DEBUG", format, args);
        va_end (args);
        
        return res;
    }

    int error(const char *format, va_list args) {
        int res;

        if (!initialized) return 0;
        if (!errorEnabled) return 0;

        res = log("ERROR", format, args);

        return res;
    }

    int warning(const char *format, va_list args)
    {
        int res;

        if (!initialized) return 0;
        if (!warningEnabled) return 0;

        res = log("WARNING", format, args);
        
        return res;
    }

    int info(const char *format, va_list args)
    {
        int res;

        if (!initialized) return 0;
        if (!informationEnabled) return 0;

        res = log("INFO", format, args);

        return res;
    }

    int infov(const char *format, va_list args)
    {
        int res;

        if (!initialized) return 0;
        if (!informationVerboseEnabled) return 0;

        res = log("INFO", format, args);

        return res;
    }

    int debug(const char *format, va_list args)
    {
        int res;

        if (!initialized) return 0;
        if (!debugEnabled) return 0;

        res = log("DEBUG", format, args);

        return res;
    }

};


#endif //DAEMON_LOG_H_
