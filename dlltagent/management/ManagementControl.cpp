/*
 * ManagementControl.cpp
 *
 *  Created on: May 29, 2021
 *      Author: rodolk
 */

#include "ManagementControl.h"

#include <thread>
#include <chrono>

#include "CommandParser.h"
#include "ManagementCommand.h"
#include "timeHelper.h"

namespace management {

ManagementControl::ManagementControl(ManagedObject& managedObject) :
        managedObject_(managedObject) {}

ManagementControl::~ManagementControl() {
    // TODO Auto-generated destructor stub
}

void ManagementControl::managementControllerThr(ManagementControl *mgmtControl) {
    ManagementControl *mgmtControlPtr = mgmtControl;
    mgmtControlPtr->timedActionsList = mgmtControlPtr->managedObject_.getTimedActionsList();

    while(!mgmtControlPtr->end_) {
        std::this_thread::sleep_for(mgmtControlPtr->sleepTimeSec);
        mgmtControlPtr->runSpecificActions();
        mgmtControlPtr->runTimedControlActions();
    }
}


void ManagementControl::runTimedControlActions() {
    struct timeval now;
    for(auto ta = timedActionsList.begin(); ta != timedActionsList.end(); ta++) {
        getTimestampNow(now);
        (*ta)(now);
    }
}

} //namespace management
