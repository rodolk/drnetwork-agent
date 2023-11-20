#ifndef HTTP_MSG_H
#define HTTP_MSG_H

#include <cstddef>
#include <stdint.h>
#include <string.h>


#define DATA_LEN 2048

#define HTTP_END_OF_HDR "\r\n\r\n"
#define HTTP_END_OF_HDR_LEN 4


using namespace std;

class HTTPMsg
{
protected:
	char data[DATA_LEN + 1];
	uint16_t dataLen{0};
	bool httpBody;
	bool methodHdr;
	bool contentHdr;
	int contentLen;
	
public:
	void setHTTPBodyFound() {httpBody = true;}
	void setMethodFound() {methodHdr = true;}
	void setContentHdrFound() {contentHdr = true;}
	void setContentLen(int _contentLen) {contentLen = _contentLen;}
	
	bool getHTTPBodyFound() const {return httpBody;}
	bool getMethodFound() const {return methodHdr;}
	bool getContentHdrFound() const {return contentHdr;}
	int getContentLen() const {return contentLen;}
	
	uint16_t getBodyLen() const
	{
		const char *bodyData = strstr(data, HTTP_END_OF_HDR);
		
		if (bodyData)
		{
			return strlen(bodyData + HTTP_END_OF_HDR_LEN);
		}
		else
		{
			return 0;
		}
	}
	
	char *getBodyData()
	{
		char *bodyData = strstr(data, HTTP_END_OF_HDR);
		
		if (bodyData)
		{
			return bodyData + HTTP_END_OF_HDR_LEN;
		}
		else
		{
			return NULL;
		}
	}

	uint16_t getDataLen() const {return dataLen;}
	
	const char *getData() const
	{
		return data; //data is always NULL terminated
	}
	
	void resetData()
	{
		data[0] = 0;
		dataLen = 0;
	}
	
	int setHttpData(char *httpData)
	{
		int httpDataLen = strlen(httpData);
		
		if (!(dataLen + httpDataLen > DATA_LEN))
		{
			strcat(data, httpData);
			dataLen += httpDataLen;
		}
		else
		{
			return -1;
		}
		
		return 0;
	}

	int setHttpData(const char *httpData, int setLen) {
		//int httpDataLen = strlen(httpData);
		
		//not controlling if httpDataLen < setLen)
		
		if (!(dataLen + setLen > DATA_LEN)) {
			strncpy(data + dataLen, httpData, setLen);
			dataLen += setLen;
			data[dataLen] = 0;
		}
		else {
			return -1;
		}
		return 0;
	}

	bool containsHeader(const char *searchText) {
	    char *ptr = strstr(data, searchText);
	    if (ptr != NULL) return true;
	    return false;
	}
};








#define ERROR_NO_BUFFER_AVAILABLE 0x01

class HTTPMsgException
{
	int type;
public:
	HTTPMsgException(int t) : type(t) {}
	int getType() const {return type;}
};

#endif //HTTP_MSG_H

