/*
 * RestConnector.h
 *
 *  Created on: Mar 26, 2020
 *      Author: rodolk
 */

#ifndef RESTCONNECTOR_H_
#define RESTCONNECTOR_H_

#include "Connector.h"

#include <cstddef>
#include <string>
#include <sstream>
#include <iostream>
#include <exception>

#include "Configuration.h"
#include "daemonLog.h"

namespace connectors {

struct requestData_t {
    uint8_t *buffer;
    size_t len;
    size_t buflen;
};

#define CHUNK_SIZE 2048

#define MAX_TIMEOUT 30

// URL:
// https://a72c3e2msk.execute-api.us-west-2.amazonaws.com/Prod/facts/a1/questions
//POST: Prod/networkevent/_bulk

using namespace std;

class RestConnector: public Connector {
public:
    class ConnectorException : public exception {
    public:
        ConnectorException(uint32_t code, const char *msg) : exception(), code_(code) {
            if (msg == NULL) {
                msg_ = string("No error message");
            } else {
                msg_ = string(msg);
            }

        }

        uint32_t getCode() const {return code_;}
        const string& getMsg() const {return msg_;}

    private:
        uint32_t code_;
        string msg_;
    };
    RestConnector() : config_(Configuration::getInstance()),
            domainName_(Configuration::getInstance().domainName),
            port_(Configuration::getInstance().servicePort) {
        std::stringstream stream;
        stream << ((config_.tlsOption) ? "https://" : "http://") << domainName_ << ":" << port_ << "/";
        uri_ = stream.str();
    }

    virtual ~RestConnector();

    virtual void initialize();

    virtual void sendData(string resource, const char *msg, uint32_t len);
    virtual int getNewCommand(requestData_t *reqData, char *& offset, uint32_t& messageLen);
    virtual void sendCommandResponse(const string& response);

    virtual void formatJSONBegin(uint8_t *data, uint32_t& offset) {
        data[0] = '[';
        offset = 1;
    }
    virtual void formatJSONNext(uint8_t *data, uint32_t& offset) {
        data[offset] = ',';
        offset++;
    }
    virtual void formatJSONEnd(uint8_t *data, uint32_t& offset) {
        data[offset - 1] = ']';
        data[offset] = '\0';
    }

private:
    Configuration& config_;
    string domainName_;
    uint16_t port_;
    string uri_;
    uint32_t maxTimeout_{MAX_TIMEOUT};
    void *dlHandle_{nullptr};

    void processHTTPMessage(requestData_t& reqData, char *& offset, uint32_t& messageLen);
};

} //namespace connectors

#endif /* RESTCONNECTOR_H_ */

