/*
 * Connector.h
 *
 *  Created on: Mar 26, 2020
 *      Author: rodolk
 */

#ifndef CONNECTOR_H_
#define CONNECTOR_H_

#include <cstdint>
#include <string>

namespace connectors {

class Connector {
public:
    Connector() {};
    virtual ~Connector() {};

    virtual void sendData(std::string resource, const char *msg, uint32_t len) = 0;
    virtual void formatJSONBegin(uint8_t *data, uint32_t& offset) = 0;
    virtual void formatJSONNext(uint8_t *data, uint32_t& offset) = 0;
    virtual void formatJSONEnd(uint8_t *data, uint32_t& offset) = 0;
};

} //namespace connectors

#endif /* CONNECTOR_H_ */
