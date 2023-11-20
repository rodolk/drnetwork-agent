/*
 * FlowsManager.cpp
 *
 *  Created on: May 28, 2021
 *      Author: rodolk
 */

#include "FlowsManager.h"

#include "applicationLog.h"

namespace flows {

std::function<void (const struct timeval&)> FlowsManager::getTimedAction() {
    return [&](const struct timeval& timeNow) -> void {
        std::unique_lock<std::mutex> lck(flowArrayMtx_);
        if (flowIdx_ == 0) return;
        if (timeNow.tv_sec - lastTimeDump_.tv_sec > 60) {
            dumpFlows(0, flowIdx_, true);
            lastTimeDump_.tv_sec = timeNow.tv_sec;
            //Caution: be careful here if we decide to dump in parallel with a different thread
            flowIdx_ = 0;
            ApplicationLog::getLog().info("TOTAL Flows saved since start: %d\n", dumpedFlowsCounter_);
        }
    };
}

} //namespace flows


