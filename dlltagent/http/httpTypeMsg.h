#ifndef HTTP_TYPE_MSG_H
#define HTTP_TYPE_MSG_H
/*
#include <cstddef>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "http/httpMsg.h"

//#define HTTP_REGISTRATION_MSG_TYPE 1
//#define HTTP_AUTH_NOTIF_MSG_TYPE 2

class HTTPRegistrationMsgType {};
class HTTPAuthNotifMsgType {};



using namespace std;

template<class T>
class HTTPTypeMsg : public HTTPMsg
{
	static HTTPTypeMsg<T> *HTTPMsgEmptyBufferListHdr;
	static HTTPTypeMsg<T> *HTTPMsgUsedBufferListHdr;
	static uint16_t numBuffers;
	static uint16_t additionalBuffers;
	HTTPTypeMsg<T> *previous;
	HTTPTypeMsg<T> *next;
	
public:
	void  *operator new(size_t);
	void operator delete(void *);
	
	static void initialize(uint16_t _numBuffers, uint16_t _additionalBuffers);
	
};





template<class T> HTTPTypeMsg<T> *HTTPTypeMsg<T>::HTTPMsgEmptyBufferListHdr  = NULL;
template<class T> HTTPTypeMsg<T> *HTTPTypeMsg<T>::HTTPMsgUsedBufferListHdr = NULL;
template<class T> uint16_t HTTPTypeMsg<T>::numBuffers = 0;
template<class T> uint16_t HTTPTypeMsg<T>::additionalBuffers = 0;

template<class T>
void *HTTPTypeMsg<T>::operator new(size_t size)
{
	if (HTTPMsgEmptyBufferListHdr)
	{
		HTTPTypeMsg<T> *emptyPtr = HTTPMsgEmptyBufferListHdr;
		HTTPMsgEmptyBufferListHdr = emptyPtr->next;
		
		if (HTTPMsgEmptyBufferListHdr) //If it was not the last buffer
		{
			emptyPtr->next->previous = NULL;
		}
		
		emptyPtr->previous = NULL; //This is redundant but anyway
		
		if (HTTPMsgUsedBufferListHdr)
		{
			HTTPMsgUsedBufferListHdr->previous = emptyPtr;
			emptyPtr->next = HTTPMsgUsedBufferListHdr;
		}
		else
		{
			emptyPtr->next = NULL;
		}
		
		HTTPMsgUsedBufferListHdr = emptyPtr;
		
		return emptyPtr;
	}
	else
	{
		throw HTTPMsgException(ERROR_NO_BUFFER_AVAILABLE);
	}
}

template<class T>
void HTTPTypeMsg<T>::operator delete(void *data)
{
	HTTPTypeMsg<T> *dataPtr = (HTTPTypeMsg<T> *)data;
	dataPtr->dataLen = 0;
	dataPtr->data[0] = 0;
	dataPtr->httpBody = false;
	dataPtr->methodHdr = false;
	dataPtr->contentHdr = false;
	dataPtr->contentLen = 0;
	
	if (dataPtr->previous)
	{
		dataPtr->previous->next = dataPtr->next;
	}
	else
	{
		HTTPMsgUsedBufferListHdr = dataPtr->next;
	}
	
	if (dataPtr->next)
	{
		dataPtr->next->previous = dataPtr->previous;
	}
	
	if (HTTPMsgEmptyBufferListHdr)
	{
		HTTPMsgEmptyBufferListHdr->previous = dataPtr;
	}
	
	dataPtr->next = HTTPMsgEmptyBufferListHdr;
	HTTPMsgEmptyBufferListHdr = dataPtr;
	dataPtr->previous = NULL;
}

template<class T>
void HTTPTypeMsg<T>::initialize(uint16_t _numBuffers, uint16_t _additionalBuffers)
{
	int i;
	
	numBuffers = _numBuffers;
	additionalBuffers = _additionalBuffers;
	
	HTTPMsgEmptyBufferListHdr  = (HTTPTypeMsg<T> *)malloc(sizeof(HTTPTypeMsg<T>) * numBuffers);
	
	if (HTTPMsgEmptyBufferListHdr )
	{
		HTTPMsgEmptyBufferListHdr[0].previous = NULL;
		HTTPMsgEmptyBufferListHdr[0].next = &HTTPMsgEmptyBufferListHdr[1];
		HTTPMsgEmptyBufferListHdr[0].dataLen = 0;
		HTTPMsgEmptyBufferListHdr[0].data[0] = 0;
		HTTPMsgEmptyBufferListHdr[0].httpBody = false;
		HTTPMsgEmptyBufferListHdr[0].methodHdr = false;
		HTTPMsgEmptyBufferListHdr[0].contentHdr = false;
		HTTPMsgEmptyBufferListHdr[0].contentLen = 0;
		
		for(i = 1; i < (numBuffers - 1); i++)
		{
			HTTPMsgEmptyBufferListHdr[i].previous = &HTTPMsgEmptyBufferListHdr[i - 1];
			HTTPMsgEmptyBufferListHdr[i].next = &HTTPMsgEmptyBufferListHdr[i + 1];
			HTTPMsgEmptyBufferListHdr[i].dataLen = 0;
			HTTPMsgEmptyBufferListHdr[i].data[0] = 0;
			HTTPMsgEmptyBufferListHdr[i].httpBody = false;
			HTTPMsgEmptyBufferListHdr[i].methodHdr = false;
			HTTPMsgEmptyBufferListHdr[i].contentHdr = false;
			HTTPMsgEmptyBufferListHdr[i].contentLen = 0;
		}
		HTTPMsgEmptyBufferListHdr[numBuffers - 1].previous = &HTTPMsgEmptyBufferListHdr[numBuffers - 2];
		HTTPMsgEmptyBufferListHdr[numBuffers - 1].next = NULL;
		HTTPMsgEmptyBufferListHdr[numBuffers - 1].dataLen = 0;
		HTTPMsgEmptyBufferListHdr[numBuffers - 1].data[0] = 0;
		HTTPMsgEmptyBufferListHdr[numBuffers - 1].httpBody = false;
		HTTPMsgEmptyBufferListHdr[numBuffers - 1].methodHdr = false;
		HTTPMsgEmptyBufferListHdr[numBuffers - 1].contentHdr = false;
		HTTPMsgEmptyBufferListHdr[numBuffers - 1].contentLen = 0;
	}
}


*/
#endif //HTTP_TYPE_MSG_H
