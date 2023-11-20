/*
 * TriggerAlgorithm.h
 *
 *  Created on: Apr 12, 2021
 *      Author: rodolk
 */

#ifndef TRIGGERALGORITHM_H_
#define TRIGGERALGORITHM_H_

class TriggerAlgorithm {
public:
    TriggerAlgorithm() {}
    virtual ~TriggerAlgorithm() {}
    enum eLBResult {LB_TRIGGER, LB_NO_TRIGGER, LB_TRIGGER_ABNORMAL};

    virtual eLBResult executeOnEvent() = 0;
};

#endif /* TRIGGERALGORITHM_H_ */
