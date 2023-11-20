/*
 * FlowsManager.h
 *
 *  Created on: May 28, 2021
 *      Author: rodolk
 */

#ifndef FLOWSMANAGER_H_
#define FLOWSMANAGER_H_

#include <mutex>
#include <functional>

#include <sys/time.h>

#include "Configuration.h"
#include "logFileManager.h"


#define MAX_FLOW_POS 400
#define HALF_FLOW_POS 200
#define HIGH_FLOWS_TO_FILE 30000


using namespace std;

namespace flows {

class FlowsManager {
public:

    FlowsManager() {}
    virtual ~FlowsManager() {}

    virtual void init(void) = 0;

    void init(const string &prefix) {
        logFileManager_ = new LogFileManager(kHighFlowsDumpedToFile_, prefix, Configuration::getInstance().logsDirectory);
        logFileManager_->init();
    }

    std::function<void (const struct timeval&)> getTimedAction();

protected:
    static const int kHighFlowsDumpedToFile_ = HIGH_FLOWS_TO_FILE;
    uint32_t flowIdx_{0};
    std::mutex flowArrayMtx_;
    struct timeval lastTimeDump_{0,0};

    uint32_t dumpedFlowsCounter_{0};
    LogFileManager *logFileManager_{nullptr};

private:
    virtual void dumpFlows(uint32_t init, uint32_t end, bool doFlush) = 0;

};

} //namespace flows

#endif /* FLOWSMANAGER_H_ */
