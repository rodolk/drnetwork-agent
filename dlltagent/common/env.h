/*
 * env.h
 *
 *  Created on: Dec 2, 2022
 *      Author: rodolk
 */

#ifndef COMMON_ENV_H_
#define COMMON_ENV_H_

#include <map>
#include <string>

extern std::map<std::string, std::string> gEnvVarsMap;
extern uint16_t gFollowPort;

#define SEARCH_HTTP_HEADER "SEARCH_HTTP_HEADER"
#define FOLLOW_PORT "FOLLOW_PORT"
#define AVOID_LIVENESS_PROBE "AVOID_LIVENESS_PROBE"


#endif /* COMMON_ENV_H_ */
