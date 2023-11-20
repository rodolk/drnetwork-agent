/*
 * QuestionCommand.h
 *
 *  Created on: May 31, 2021
 *      Author: rodolk
 */

#ifndef QUESTIONCOMMAND_H_
#define QUESTIONCOMMAND_H_

#include <string>

#include "ManagementCommand.h"

namespace management {

using namespace std;

class QuestionCommand: public ManagementCommand {
public:
    QuestionCommand(string questionId, string srcIP, uint16_t srcPort,
            string dstIP, uint16_t dstPort, string code) :
                questionId_(questionId), srcIP_(srcIP), dstIP_(dstIP),
                srcPort_(srcPort), dstPort_(dstPort), code_(code) {}
    virtual ~QuestionCommand();

    virtual std::string& execute(ManagedObject& managedObj);

private:
    std::string questionId_;
    std::string srcIP_;
    std::string dstIP_;
    uint16_t srcPort_;
    uint16_t dstPort_;
    string code_;
};

} //namespace management

#endif /* QUESTIONCOMMAND_H_ */
