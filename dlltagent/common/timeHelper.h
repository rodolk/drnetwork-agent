/*
 * timeHelper.h
 *
 *  Created on: May 28, 2021
 *      Author: rodolk
 */

#ifndef TIMEHELPER_H_
#define TIMEHELPER_H_


#include <string>
#include <cstring>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <ctime>

using namespace std;

/**
 * Description: getNowTimeAsString returns now time as a string in format
 *              YYYY_MM_DD_HH_mm_ss
 *
 * @return string with now time formatted
 */
inline string getNowTimeAsString() {
    stringstream newSstring;
    using namespace std::chrono;
    system_clock::time_point now = system_clock::now();
    time_t tt = system_clock::to_time_t(now);
    tm utc_tm = *gmtime(&tt);
    newSstring << utc_tm.tm_year + 1900 << '_';
    newSstring << setw(2) << setfill('0');
    newSstring << utc_tm.tm_mon + 1 << '_';
    newSstring << setw(2) << setfill('0');
    newSstring << utc_tm.tm_mday << '_';
    newSstring << setw(2) << setfill('0');
    newSstring << utc_tm.tm_hour << '_';
    newSstring << setw(2) << setfill('0');
    newSstring << utc_tm.tm_min << '_';
    newSstring << setw(2) << setfill('0');
    newSstring << utc_tm.tm_sec;

    return newSstring.str();
}

/**
 * Description: this function sets timeStamp with now time as milliseconds since the epoch in GMT
 *              std::chrono::system_clock::now().time_since_epoch() returns time in GMT
 *              usec are zeroed here
 *
 * @param timeStamp is a reference to a struct timeval where the now time will be set
 *
 */
inline void getTimestampNow(struct timeval& timeStamp) {
    auto millisecs = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch());
    timeStamp.tv_sec = millisecs.count()/1000;
    timeStamp.tv_usec = (millisecs.count()%1000) * 1000;
}

inline const char *getNowAsLogFormat() {
    static char tmbuf[64];
    struct tm *tmGMTNow;
    struct timeval timeStamp;

    getTimestampNow(timeStamp);
    time_t nowtime = timeStamp.tv_sec;
    tmGMTNow = gmtime(&nowtime);

    std::strftime(tmbuf, sizeof(tmbuf), "%Y-%m-%d %H:%M:%S", tmGMTNow);
    sprintf(tmbuf + strlen(tmbuf), ".%3.3u", (uint32_t)(timeStamp.tv_usec/1000));
    return tmbuf;
}


#endif /* TIMEHELPER_H_ */
