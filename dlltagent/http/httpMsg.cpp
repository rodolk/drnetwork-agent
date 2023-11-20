/*
#include "httpMsg.h"

#include <stdint.h>
#include <stdlib.h>

HTTPMsg *HTTPMsg::HTTPMsgEmptyBufferListHdr  = NULL;
HTTPMsg *HTTPMsg::HTTPMsgUsedBufferListHdr = NULL;
uint16_t HTTPMsg::numBuffers = 0;
uint16_t HTTPMsg::additionalBuffers = 0;

void *HTTPMsg::operator new(size_t size)
{
	if (HTTPMsgEmptyBufferListHdr)
	{
		HTTPMsg *emptyPtr = HTTPMsgEmptyBufferListHdr;
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

void HTTPMsg::operator delete(void *data)
{
	HTTPMsg *dataPtr = (HTTPMsg *)data;
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

void HTTPMsg::initialize(uint16_t _numBuffers, uint16_t _additionalBuffers)
{
	int i;
	
	numBuffers = _numBuffers;
	additionalBuffers = _additionalBuffers;
	
	HTTPMsgEmptyBufferListHdr  = (HTTPMsg *)malloc(sizeof(HTTPMsg) * numBuffers);
	
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
