#ifndef HTTP_PROCESSOR_H
#define HTTP_PROCESSOR_H
/*
#include <stdint.h>

#include "http/httpMsg.h"


#define HTTP_PROCESSOR_CONTENT_LEN_ERR -2
#define HTTP_PROCESSOR_METHOD_ERR -1
#define HTTP_PROCESSOR_MSG_HDR_END 0
#define HTTP_PROCESSOR_MSG_HDR_INCOMPLETE 1
#define HTTP_PROCESSOR_MSG_BODY_EXTRALENGTH_ERROR -1
#define HTTP_PROCESSOR_MSG_BODY_COMPLETE 0
#define HTTP_PROCESSOR_MSG_BODY_INCOMPLETE 1


class HTTPProcessor
{
private:
	static HTTPProcessor *instance;
	HTTPProcessor() {}
	
public:
	static HTTPProcessor* getInstance()
	{
		if (instance != NULL)
		{
			return instance;
		}
		else
		{
			instance = new HTTPProcessor();
			return instance;
		}
	}
	
	int processInitialHTTPHdr(char *httpHdrData, HTTPMsg &httpMsg, char *&nxtChar, const char *methodEndpoint, uint8_t methodEndPointLen);
	int processRestOfHTTPHdr(char *httpHdrData, HTTPMsg &httpMsg, char *&nxtChar, const char *methodEndpoint, uint8_t methodEndPointLen);
	int processHTTPBody(char *httpBodyData, HTTPMsg& httpMsg, char *&outBodyData, bool initial);
};

*/
#endif //HTTP_PROCESSOR_H
