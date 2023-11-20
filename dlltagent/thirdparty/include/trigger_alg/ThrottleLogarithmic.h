/*
 * ThrottleLogarithmic.h
 *
 *  Created on: Apr 12, 2021
 *      Author: rodolk
 */

#ifndef THROTTLE_LOGARITHMIC_H_
#define THROTTLE_LOGARITHMIC_H_

#include <cstdint>
#include <chrono>

#include "TriggerAlgorithm.h"

class ThrottleLogarithmic : public TriggerAlgorithm {
public:
    ThrottleLogarithmic() : TriggerAlgorithm() {}
    virtual ~ThrottleLogarithmic() {}

    eLBResult executeOnEvent() {
        eLBResult res = LB_TRIGGER;

        using namespace std::chrono;
        seconds msNow = duration_cast<seconds>(system_clock::now().time_since_epoch());
        count_ ++;

        if (count_ < 4) {
            if (count_ == 1) lastTimeCheck_ = msNow;
        } else if (count_ == nextTrigger_) {
            if (nextTrigger_ < 10000000) {    // 10M
                nextTrigger_ = nextTrigger_ * 10;
            } //Don't need else because count will be always greater than 1M until recycleSec_
        } else {
            system_clock::duration dur = msNow - lastTimeCheck_;
            if (std::chrono::duration_cast<std::chrono::seconds>(dur).count() < recycleSec_) {
                if (count_ > 0xFFFFFFF0) {
                    if (count_ < 0xFFFFFFF3) { //We return this only twice
                        res = LB_TRIGGER_ABNORMAL;
                    } else {
                        count_ = 0xFFFFFFF3;
                    }
                } else {
                    res = LB_NO_TRIGGER;
                }
            } else {
                count_ = 0;
                nextTrigger_ = 10;
                lastTimeCheck_ = msNow;
            }
        }

        return res;
    };

private:
    uint32_t nextTrigger_{10};
    uint32_t count_{0};
    uint32_t recycleSec_{86400};
    std::chrono::seconds lastTimeCheck_{}; //duration_cast<milliseconds>(system_clock::duration::zero());
};

#endif /* THROTTLE_H_ */
