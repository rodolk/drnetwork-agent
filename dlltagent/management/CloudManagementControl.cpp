/*
 * CloudManagementControl.cpp
 *
 *  Created on: May 29, 2021
 *      Author: rodolk
 */

#include "CloudManagementControl.h"

#include <thread>
#include <chrono>

#include "RestConnector.h"
#include "CommandParser.h"
#include "ManagementCommand.h"
#include "timeHelper.h"

namespace management {

CloudManagementControl::CloudManagementControl(ManagedObject& managedObject, connectors::RestConnector& restCtor) :
        ManagementControl(managedObject),
        restCtor_(restCtor) {

    reqData_.buffer = (uint8_t *)malloc(CHUNK_SIZE);
    reqData_.buflen = CHUNK_SIZE;
    reqData_.len = 0;

    cmdParser_ = new CommandParser();
}

CloudManagementControl::~CloudManagementControl() {
    // TODO Auto-generated destructor stub
}

void CloudManagementControl::runSpecificActions() {
    reqData_.len = 0;
    restCtor_.getNewCommand(&reqData_, cmdOffset_, cmdLen_);
    cmdParser_->parse((const char *)reqData_.buffer, ((uint8_t *)cmdOffset_ - reqData_.buffer), cmdLen_);
    ManagementCommand *mgmtCmd = cmdParser_->getNextCommand();
    if (mgmtCmd != nullptr) {
        string& respuestaStr = mgmtCmd->execute(getManagedObject());
        restCtor_.sendCommandResponse(respuestaStr);
        //Need to delete object
        delete &respuestaStr;
    } else {
        std::cout << "NULL ptr" << std::endl;
    }
}

} //namespace management
