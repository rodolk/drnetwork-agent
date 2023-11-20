/*
 * IRestPlugin.h
 *
 *  Created on: Aug 31, 2021
 *      Author: rodolk
 */

#ifndef PLUGINS_IRESTPLUGIN_H_
#define PLUGINS_IRESTPLUGIN_H_

#include <cstddef>
#include <string>
#include <sstream>
#include <iostream>

#include "daemonLog.h"

namespace plugins {

struct requestData_t {
    uint8_t *buffer;
    size_t len;
    size_t buflen;
};

class IRestPlugin {
public:
    IRestPlugin() {}

    virtual ~IRestPlugin() {}

    virtual void initialize(DaemonLog *logging) = 0;
    virtual void sendData(std::string resource, const char *msg, uint16_t len) = 0;
    virtual int getNewCommand(requestData_t *reqData, char *& offset, uint32_t& messageLen) = 0;
};

} //namespace plugins



#endif /* PLUGINS_IRESTPLUGIN_H_ */
