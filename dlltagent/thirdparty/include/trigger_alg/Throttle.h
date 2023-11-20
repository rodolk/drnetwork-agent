/*
 * Throttle.h
 *
 *  Created on: Apr 12, 2021
 *      Author: rodolk
 */

#ifndef THROTTLE_H_
#define THROTTLE_H_

#include <cstdint>
#include <chrono>

#include "TriggerAlgorithm.h"

class Throttle : public TriggerAlgorithm {
public:
    Throttle(uint32_t initialTrigger, uint32_t silentTimeSec) : TriggerAlgorithm(), initialTrigger_(initialTrigger), silentTimeSec_(silentTimeSec) {
        if (initialTrigger == 0) {
            initialTrigger_ = 1;
        }
    }
    virtual ~Throttle() {}

    eLBResult executeOnEvent() {
        eLBResult res = LB_TRIGGER;

        using namespace std::chrono;
        seconds secNow = duration_cast<seconds>(system_clock::now().time_since_epoch());
        system_clock::duration dur = secNow - lastTimeCheck_;

        if (count_ < initialTrigger_) {
            count_ ++;
            if (std::chrono::duration_cast<std::chrono::seconds>(dur).count() > silentTimeSec_) {
                count_ = 1;
            }
            lastTimeCheck_ = secNow;
        } else {
            if (std::chrono::duration_cast<std::chrono::seconds>(dur).count() < silentTimeSec_) {
                res = LB_NO_TRIGGER;
            } else {
                count_ = 1;
                lastTimeCheck_ = secNow;
            }
        }

        return res;
    };

private:
    int32_t initialTrigger_;
    int32_t count_{0};
    uint32_t silentTimeSec_;
    std::chrono::seconds lastTimeCheck_{}; //duration_cast<seconds>(system_clock::duration::zero());
};

#endif /* THROTTLE_H_ */
