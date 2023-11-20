/*
 * ManagementControl.h
 *
 *  Created on: May 29, 2021
 *      Author: rodolk
 */

#ifndef MANAGEMENTCONTROL_H_
#define MANAGEMENTCONTROL_H_

#include <chrono>
#include <list>
#include <functional>

#include "CommandParser.h"
#include "ManagedObject.h"

namespace management {

class ManagementControl {
public:
    static void managementControllerThr(ManagementControl *mgmtControl);

    ManagementControl(ManagedObject& managedObject);
    virtual ~ManagementControl();

    void setEnd() {end_ = true;}

    void registerTimedAction(std::function<void (const struct timeval&)> timedAction) {
        timedActionsList.push_back(timedAction);
    }

protected:
    ManagedObject& getManagedObject() {return managedObject_;}

private:
    std::chrono::duration<int> sleepTimeSec = 30s;
    bool end_{false};
    ManagedObject& managedObject_;
    std::list<std::function<void (const struct timeval&)>> timedActionsList;

    void runTimedControlActions();

    virtual void runSpecificActions() {}

};

} //namespace management

#endif /* MANAGEMENTCONTROL_H_ */
