/*
 * RestConnector.cpp
 *
 *  Created on: Mar 26, 2020
 *      Author: rodolk
 */

#include "RestConnector.h"

#include <memory>
#include <exception>

#include <string.h>
#include <dlfcn.h>

#include "IRestPlugin.h"
#include "Configuration.h"
#include "applicationLog.h"

#define LIB_REST_CONN "libdlltrestconnector.so"

extern "C" {
std::shared_ptr<plugins::IRestPlugin> createRestPlugin(const std::string& uri,
        const bool tlsOption,
        const bool tlsIgnoreSrvCertOption,
        const std::string& questionResource);
}


namespace connectors {

std::shared_ptr<plugins::IRestPlugin> (*createRestPluginObject) (const std::string&,
        const bool, const bool, const std::string&);

std::shared_ptr<plugins::IRestPlugin> gRESTPlugin;

RestConnector::~RestConnector() {
    gRESTPlugin.reset();
    if (dlHandle_) dlclose(dlHandle_);
}

typedef struct curlHTTPMsg {
  const char *readptr;
  size_t sizeleft;
} curlHTTPMsg_t;

void RestConnector::initialize() {
    dlHandle_ = dlopen(LIB_REST_CONN, RTLD_NOW);
    if (NULL == dlHandle_) {
        const char *dlerrorPtr = dlerror();
        string absPathName;
        ApplicationLog::getLog().debug("Error loading shared library %s: %s\n", LIB_REST_CONN, dlerrorPtr);
        auto libPathIter = Configuration::getInstance().libPathList.begin();
        while(NULL == dlHandle_ && libPathIter != Configuration::getInstance().libPathList.end()) {
            absPathName = *libPathIter + "/" + LIB_REST_CONN;
            ApplicationLog::getLog().debug("Searching shared library: %s\n", absPathName.c_str());
            dlHandle_ = dlopen(absPathName.c_str(), RTLD_NOW);
            if (NULL == dlHandle_) {
                dlerrorPtr = dlerror();
                ApplicationLog::getLog().debug("Error loading shared library %s: %s\n", absPathName.c_str(), dlerrorPtr);
            }
            libPathIter++;
        }
        if (NULL == dlHandle_) {
            throw ConnectorException(1, dlerrorPtr);
        }
    }

    dlerror();

    void *pluginFunc = dlsym(dlHandle_, "createRestPlugin");

    if (NULL == pluginFunc) {
        dlclose(dlHandle_);
        const char *err = dlerror();
        if (err == NULL) {
            throw ConnectorException(2, "Symbol createRestPlugin not found");
        } else {
            throw ConnectorException(2, err);
        }
    }
    dlerror();

    createRestPluginObject = reinterpret_cast<std::shared_ptr<plugins::IRestPlugin> (*) (
            const std::string&,
            const bool, const bool,
            const std::string&)>(pluginFunc);

    gRESTPlugin = createRestPluginObject(uri_, config_.tlsOption, config_.tlsIgnoreSrvCertOption,
            config_.questionResource);

    if (nullptr == gRESTPlugin) {
        dlclose(dlHandle_);
        throw ConnectorException(3, "Could not create plugin object");
    }
    gRESTPlugin->initialize(&(ApplicationLog::getLog()));

    dlerror();
}

void RestConnector::sendData(string resource, const char *msg, uint32_t len) {
    gRESTPlugin->sendData(resource, msg, len);
}

// URL:
// https://a72c3e2msk.execute-api.us-west-2.amazonaws.com/Prod/facts/a1/questions

//TODO: avoid multi-threading

int RestConnector::getNewCommand(requestData_t *reqData, char *& offset, uint32_t& messageLen) {
    return gRESTPlugin->getNewCommand((plugins::requestData_t *)reqData, offset, messageLen);
}


void RestConnector::sendCommandResponse(const string& response) {
    uint16_t len = response.length();
    sendData(config_.responseResource, response.c_str(), len);
}

} //namespace connectors
















