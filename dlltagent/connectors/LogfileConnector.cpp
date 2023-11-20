/*
 * LogfileConnector.cpp
 *
 *  Created on: Mar 26, 2020
 *      Author: rodolk
 */

#include "LogfileConnector.h"

namespace connectors {

LogfileConnector::~LogfileConnector() {
    eventsFile_.close();
}

void LogfileConnector::sendData(string resource, const char *msg, uint32_t len) {
    if (bytesToFileCounter_ > kHighBytesToFile_) {
        bytesToFileCounter_ = 0;
        eventsFile_.close();
        string filename = createFileName();
        eventsFile_.open(filename);
        eventsFileInitTime_ = chrono::system_clock::now();
    }

    eventsFile_.write(msg, len);
    eventsFile_ << endl;

    bytesToFileCounter_ += len;
    bytesTotalCounter_ += bytesToFileCounter_;

    eventsFile_.flush();
}

} //namespace connectors


