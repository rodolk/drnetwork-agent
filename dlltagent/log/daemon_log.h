#ifndef DAEMON_LOG_C__H_
#define DAEMON_LOG_C_H_


int logerror(const char *format, ...);
int logwarning(const char *format, ...);
int loginfo(const char *format, ...);
int loginfov(const char *format, ...);
int logdebug(const char *format, ...);
int initializeWithFile(const char *initialLogFile, const char *directory, const char *_logFileName, unsigned int logLevel);
int initialize(const char *initialLogFile);

#endif //DAEMON_LOG_C__H_
