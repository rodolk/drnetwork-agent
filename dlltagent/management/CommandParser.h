/*
 * CommandParser.h
 *
 *  Created on: May 31, 2021
 *      Author: rodolk
 */

#ifndef COMMANDPARSER_H_
#define COMMANDPARSER_H_


#include <cstdint>
#include <iostream>
#include <sstream>

#include "json/json.h"
#include "ManagementCommand.h"
#include "QuestionCommand.h"

namespace management {

class CommandParser {
public:
    CommandParser();
    virtual ~CommandParser();

    /**
     * Receives a C string in json format, parses it and initializes an iterator for all commands.
     * Then each command can later be obtained with getNextCommand
     *
     * @param jsonData  the C string in Json format
     * @param offset    position in jsonData to begin to parse
     * @param endOffset position in jsonData to end parsing, inclusive.
     */
    void parse(const char *jsonData, uint32_t offset, uint32_t endOffset) {
        jsonData_  = jsonData;
        offset_    = offset;
        endOffset_ = endOffset;

        std::string cmdString(jsonData + offset, endOffset - offset);
        std::istringstream is(cmdString);
        std::string errs;

        bool parsingSuccessful = Json::parseFromStream(charReaderBuilder_, is, &root_, &errs);
        if (!parsingSuccessful) {
            std::cout << "Error parsing the string: " << cmdString << std::endl;
            std::cout << "Errs: " << errs << std::endl;
        }

        printf(" {type=[%d], size=%d}", root_.type(), root_.size());

        iterator_ = root_.begin();
    }

    //TODO:Need to parse jsonData

    /**
     * Retrieve the next command from the jsonData parsed by parse.
     *
     * @return for now it always returns a QuestionCommand.
     *
     * @caution: parse has to be called before to set the iterator.
     */
    ManagementCommand *getNextCommand() {
        if (iterator_ != root_.end()) {
            string questionId;
            string srcIP;
            string dstIP;
            uint16_t srcPort;
            uint16_t dstPort;
            string code;

            std::cout << *iterator_ << std::endl;

            questionId = iterator_->get("id", "0").asString();
            srcIP = iterator_->get("srcIp", "0.0.0.0").asString();
            dstIP = iterator_->get("dstIp", "0.0.0.0").asString();
            code = iterator_->get("code", "0.0.0.0").asString();
            srcPort = iterator_->get("srcPort", 0).asUInt();
            dstPort = iterator_->get("dstPort", 0).asUInt();

            std::cout << "VALUES: " << questionId << ", srcIP: " << srcIP
                    << ", dstIP: " << dstIP << ", srcPort: " << srcPort << ", dstPort: " << dstPort << ", code: " << code << std::endl;

            return new QuestionCommand(questionId, srcIP, srcPort, dstIP, dstPort, code);
        } else {
            std::cout << "END OF ITERATOR" << std::endl;
            return nullptr;
        }
    }

private:
    const char *jsonData_;
    uint32_t offset_;
    uint32_t endOffset_;
    Json::Value root_;
    Json::CharReaderBuilder charReaderBuilder_;
    Json::Value::const_iterator iterator_;


};

} //namespace management

#endif /* COMMANDPARSER_H_ */
