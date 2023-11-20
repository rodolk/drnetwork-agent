/*
 * LogfileConnector.h
 *
 *  Created on: Mar 26, 2020
 *      Author: rodolk
 */

#ifndef LOGFILE_CONNECTOR_H_
#define LOGFILE_CONNECTOR_H_

#include "Connector.h"

#include <cstddef>
#include <string>
#include <iostream>
#include <fstream>
#include <chrono>
#include <mutex>

#include "Configuration.h"
#include "timeHelper.h"


namespace connectors {

#define CONNECTORS_HIGH_BYTES_TO_FILE 10000000


using namespace std;

class LogfileConnector: public Connector {
public:
    LogfileConnector() : config_(Configuration::getInstance()) {
        string filename = createFileName();
        eventsFile_.open(filename);
        eventsFileInitTime_ = chrono::system_clock::now();
    }

    virtual ~LogfileConnector();

    virtual void sendData(string resource, const char *msg, uint32_t len);

    virtual void formatJSONBegin(uint8_t *data, uint32_t& offset) {}
    virtual void formatJSONNext(uint8_t *data, uint32_t& offset) {
        data[offset] = '\n';
        offset++;
    }
    virtual void formatJSONEnd(uint8_t *data, uint32_t& offset) {
        offset--;
        data[offset] = '\0';
    }

private:
    static const int kHighBytesToFile_ = CONNECTORS_HIGH_BYTES_TO_FILE;

    Configuration& config_;

    ofstream eventsFile_;
    chrono::system_clock::time_point eventsFileInitTime_;
    uint32_t bytesTotalCounter_{0};
    uint32_t bytesToFileCounter_{0};

    string createFileName() {
        string filename = Configuration::getInstance().logsDirectory + "/netwevents_" + getNowTimeAsString() + ".log";
        return filename;
    }
};

} //namespace connectors

#endif /* LOGFILE_CONNECTOR_H_ */
