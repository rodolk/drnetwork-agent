/*
 * LeakyBucket.h
 *
 *  Created on: Apr 12, 2021
 *      Author: rodolk
 */

#ifndef LEAKYBUCKET_H_
#define LEAKYBUCKET_H_

#include <chrono>
#include <cstdint>

#include "TriggerAlgorithm.h"

class LeakyBucket : public TriggerAlgorithm {
public:
    LeakyBucket(int32_t threshold, uint32_t msDecr, uint32_t decr = 1, uint32_t incr = 1) :
        TriggerAlgorithm(), threshold_(threshold), incr_(incr), msDecr_(msDecr), decr_(decr) {
        if (msDecr == 0 || decr == 0) {
            msDecr_ = 1;
        }
    }
    virtual ~LeakyBucket() {}

    eLBResult executeOnEvent() {
        eLBResult res = LB_TRIGGER;

        using namespace std::chrono;
        milliseconds msNow = duration_cast<milliseconds>(system_clock::now().time_since_epoch());

        if (count_ > 0) {
            count_ += incr_;
            system_clock::duration dur = msNow - lastTimeCheck_;
            uint32_t totDecr = (decr_ * (std::chrono::duration_cast<std::chrono::milliseconds>(dur).count() % msDecr_));
            count_ = (count_ > totDecr) ? count_ - totDecr : 1;
            if (count_ >= threshold_) {
                count_ = 1;
            } else {
                res = LB_NO_TRIGGER;
            }
        } else {
            count_ = 1;
        }

        lastTimeCheck_ = msNow;

        return res;
    };

private:
    int32_t threshold_;
    int32_t count_{0};
    uint32_t incr_;
    uint32_t msDecr_;
    uint32_t decr_;
    std::chrono::milliseconds lastTimeCheck_{}; //duration_cast<milliseconds>(system_clock::duration::zero());
};

#endif /* LEAKYBUCKET_H_ */
