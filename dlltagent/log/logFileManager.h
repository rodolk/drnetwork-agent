/*
 * logFileManager.h
 *
 *  Created on: May 30, 2023
 *      Author: rodolk
 */

#ifndef LOG_LOGFILEMANAGER_H_
#define LOG_LOGFILEMANAGER_H_

#include <iostream>
#include <fstream>
#include <chrono>

#include "timeHelper.h"

using namespace std;

#define HIGH_LINES_TO_FILE 30000

class LogFileManager {
public:
    LogFileManager() {}
    LogFileManager(uint32_t highLines, const string& filePrefix, string logsDirectory):highLinesDumpedToFile_(highLines),
            filePrefix_(filePrefix), logsDirectory_(logsDirectory) {}
    virtual ~LogFileManager() {
        logsFile_.close();
    }

    bool init() {
        currFilename_ = createFileName();
        logsFile_.open(currFilename_);
        if (logsFile_.is_open()) {
            logsFileInitTime_ = chrono::system_clock::now();
            return true;
        } else {
            cerr << "Error opening file " << currFilename_ << " for write" << endl;
            return false;
        }
    }

    int processRotation() {
        if (dumpedLinesToFileCounter_ > highLinesDumpedToFile_) {
            dumpedLinesToFileCounter_ = 0;
            logsFile_.close();
            currFilename_ = createFileName();
            logsFile_.open(currFilename_);
            if (logsFile_.is_open()) {
                logsFileInitTime_ = chrono::system_clock::now();
                return 0;
            } else {
                cerr << "Error opening file " << currFilename_ << " for write" << endl;
                return -1;
            }
        }
        return 1;
    }

    void incLine() {
        dumpedLinesToFileCounter_++;
    }

    ofstream& getFileStream() {
        return logsFile_;
    }

    void flush() {
        logsFile_.flush();
    }

    const string& getCurrFilename() {return currFilename_;}
    const string& getLogsDirectory() {return logsDirectory_;}

private:
    uint32_t highLinesDumpedToFile_{HIGH_LINES_TO_FILE};

    ofstream logsFile_;
    chrono::system_clock::time_point logsFileInitTime_;
    uint32_t dumpedLinesTotalCounter_{0};
    uint32_t dumpedLinesToFileCounter_{0};
    string filePrefix_{"logs"};
    string currFilename_;
    string logsDirectory_{"."};

    string createFileName() {
        string filename = logsDirectory_ + "/" + filePrefix_ + "_" + getNowTimeAsString() + ".log";
        return filename;
    }

};

#endif /* LOG_LOGFILEMANAGER_H_ */
