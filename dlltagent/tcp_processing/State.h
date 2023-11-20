/*
 * State.h
 *
 *  Created on: Apr 6, 2020
 *      Author: rodolk
 */

#ifndef STATE_H_
#define STATE_H_

class State {
public:
    State();
    virtual ~State();

    virtual State *process(bool& processAgain) = 0;
    virtual State *init() = 0;
};

#endif /* STATE_H_ */
