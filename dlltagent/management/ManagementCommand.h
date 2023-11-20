/*
 * ManagementCommand.h
 *
 *  Created on: May 31, 2021
 *      Author: rodolk
 */

#ifndef MANAGEMENTCOMMAND_H_
#define MANAGEMENTCOMMAND_H_

#include <string>

#include "ManagedObject.h"

namespace management {

class ManagementCommand {
public:
    ManagementCommand() {}
    virtual ~ManagementCommand() {}

    virtual std::string& execute(ManagedObject& managedObj) = 0;
};

} //namespace management

#endif /* MANAGEMENTCOMMAND_H_ */
