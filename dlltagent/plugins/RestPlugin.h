/*
 * RestPlugin.h
 *
 *  Created on: Mar 26, 2020
 *      Author: rodolk
 */

#ifndef RESTPLUGIN_H_
#define RESTPLUGIN_H_

#include <cstddef>
#include <string>

#include "IRestPlugin.h"
#include "daemonLog.h"


namespace plugins {

#define CHUNK_SIZE 2048

#define MAX_TIMEOUT 30



// URL:
// https://a72c3e2msk.execute-api.us-west-2.amazonaws.com/Prod/facts/a1/questions
//POST: Prod/networkevent/_bulk

using namespace std;

class RestPlugin : public IRestPlugin{
public:
    RestPlugin(const string& uri, const bool tlsOption, const bool tlsIgnoreSrvCertOption,
            const string& questionResource) : IRestPlugin(),
                uri_(uri), tlsOption_(tlsOption), tlsIgnoreSrvCertOption_(tlsIgnoreSrvCertOption),
                questionResource_(questionResource) {
    }

    virtual ~RestPlugin();

    virtual void initialize(DaemonLog *logging) {
        logging_ = logging;
    }
    virtual void sendData(string resource, const char *msg, uint16_t len);
    virtual int getNewCommand(requestData_t *reqData, char *& offset, uint32_t& messageLen);

private:
    string uri_;
    bool tlsOption_;
    bool tlsIgnoreSrvCertOption_;
    string questionResource_;
    uint32_t maxTimeout_{MAX_TIMEOUT};
    DaemonLog *logging_{nullptr};
    static size_t read_callback(void *dest, size_t size, size_t nmemb, void *userp);
    static size_t getNewCommandCallback(const char *ptr, size_t size, size_t nmemb, void *userdata);

    void processHTTPMessage(requestData_t& reqData, char *& offset, uint32_t& messageLen);
};

} //namespace plugins

#endif /* RESTPLUGIN_H_ */

