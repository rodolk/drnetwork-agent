/*
 * QuestionCommand.cpp
 *
 *  Created on: May 31, 2021
 *      Author: rodolk
 */

#include "QuestionCommand.h"

#include <string>
#include <sstream>

namespace management {

QuestionCommand::~QuestionCommand() {
    // TODO Auto-generated destructor stub
}

using namespace std;


/**
 * result values:
 *        0: I haven't seen that IP address in the last 6 minutes
 *        1: I saw the IP address but not the port
 *        2: I saw both the address and the port
 *
 * @param managedObj that implements the ManagedObject interface and can tell you if
 *                   an IP address was seen in the last minute
 * @return  a string reference to a string containing the JSON response from this command.
 *          This string needs to be deleted by caller.
 *
 * @Caution
 * result today is only set to 0 or 2 because we aren't checking port.
 */

//TODO: result here is set to 0 or 2. This is because we are not checking port, we're only checking IP addr
//We need to add port check

string& QuestionCommand::execute(ManagedObject& managedObj) {
    const char *ipCString = srcIP_.c_str();
    bool result = managedObj.haveYouSeenThisIPLAstMinute(ipCString);
    stringstream resSStream;
    resSStream << "[{\"questionId\":\"" << questionId_ << "\","
            << "\"answer\": {\"srcIp\":\"" << srcIP_ << "\","
            << "\"dstIp\":\"" << dstIP_ << "\","
            << "\"srcPort\":" << srcPort_ << ","
            << "\"dstPort\":" << dstPort_ << ","
            << "\"code\":\"" << code_ << "\","
            << "\"cmd\": 1,"
            << "\"result\": " << (result ? 2 : 0)
            << "}}]";

    string *resString = new std::string(resSStream.str());
    return *resString;
}

} //namespace management
