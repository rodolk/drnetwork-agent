/*
 * CloudManagementControl.h
 *
 *  Created on: May 29, 2021
 *      Author: rodolk
 */

#ifndef CLOUD_MANAGEMENTCONTROL_H_
#define CLOUD_MANAGEMENTCONTROL_H_

#include <chrono>
#include <list>
#include <functional>

#include "RestConnector.h"
#include "CommandParser.h"
#include "ManagedObject.h"
#include "ManagementControl.h"

namespace management {

class CloudManagementControl : public ManagementControl {
public:
    CloudManagementControl(ManagedObject& managedObject, connectors::RestConnector& restCtor);
    virtual ~CloudManagementControl();

private:
    connectors::RestConnector& restCtor_;
    CommandParser *cmdParser_;
    connectors::requestData_t reqData_;
    char *cmdOffset_{nullptr};
    uint32_t cmdLen_{0};

    virtual void runSpecificActions();

};

} //namespace management

#endif /* CLOUD_MANAGEMENTCONTROL_H_ */
