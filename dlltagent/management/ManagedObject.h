/*
 * ManagedObject.h
 *
 *  Created on: May 31, 2021
 *      Author: rodolk
 */

#ifndef MANAGEDOBJECT_H_
#define MANAGEDOBJECT_H_

#include <functional>
#include <list>

namespace management {

class ManagedObject {
public:
    ManagedObject() {}
    virtual ~ManagedObject() {}

    virtual bool haveYouSeenThisIPLAstMinute(const char *ipCString) = 0;

    virtual std::list<std::function<void (const struct timeval&)>> getTimedActionsList() = 0;
};

} //namespace management

#endif /* MANAGEDOBJECT_H_ */
