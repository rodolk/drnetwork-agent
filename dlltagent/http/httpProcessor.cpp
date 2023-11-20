/*
#include "http/httpProcessor.h"

#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

#include "http/httpMsg.h"

#define CONTENT_HDR_VALUE_LEN 3

#define HTTP_CONTENT_HDR "Content-Length: "
#define HTTP_CONTENT_HDR_LEN 16
#define HTTP_END_OF_L "\r\n"


HTTPProcessor *HTTPProcessor::instance = NULL;
*/
/**********************************************************************************************************************
 * Name: processInitialHTTPHdr
 * Description: This function is called for processing an HTTP header for first time. The header could be complete or
 * partial. If it is partial, INCOMPLETE will be returned and, when the next part of the header is received, it will be
 * passed to function processRestOfHTTPHdr. This function (processInitialHTTPHdr) is called only the first time.
 *
 * Arguments:
 * char *	httpHdrData	Pointer to C String containing received header data
 * HTTPMsg&	httpMsg		HTTP msg being received and processed
 * char *&	nxtChar		out pointer to the next char to be processed. It will point to the edn of header chars
 *						if the header is complete.
 * int&		contentLen	Value of ContentLength header if it is found in the data received.
 * 
 * Returns
 * int 				result of HDR processing 
 *					HTTP_PROCESSOR_MSG_HDR_END
 *					HTTP_PROCESSOR_MSG_HDR_INCOMPLETE
 *					HTTP_PROCESSOR_CONTENT_LEN_ERR
 *					HTTP_PROCESSOR_METHOD_ERR
 *
 * Note:
 * httpHdrData must be NULL terminated C String.
 *********************************************************************************************************************/
/*
int HTTPProcessor::processInitialHTTPHdr(char *httpHdrData, HTTPMsg &httpMsg, char *&nxtChar, const char *methodEndpoint, uint8_t methodEndPointLen)
{
	char *ptr = httpHdrData;
	char *contentPtr;
	char *methodPtr;
	char *auxPtr;
	char *endOfHdr;
	char *eol;
	int res;
	int contentLen;

	methodPtr = strstr(ptr, methodEndpoint);
	
	if (methodPtr)
	{
		httpMsg.setMethodFound();
		ptr += methodEndPointLen;
		contentPtr = strstr(ptr, HTTP_CONTENT_HDR);
		
		if (contentPtr)
		{
			eol = strstr(contentPtr, HTTP_END_OF_L);
			if (eol)
			{
				*eol = 0;
				httpMsg.setContentHdrFound();
				errno = 0;
				contentLen = strtol(contentPtr + HTTP_CONTENT_HDR_LEN, &auxPtr, 10);
				
				if (contentLen == 0)
				{
					if (!(*auxPtr == 0 && errno == 0))
					{
						return HTTP_PROCESSOR_CONTENT_LEN_ERR;
					}
				}
				
				httpMsg.setContentLen(contentLen);
				
				*eol = '\r';
				endOfHdr = strstr(eol, HTTP_END_OF_HDR);
				
				if (endOfHdr)
				{
					nxtChar = endOfHdr;
					res = HTTP_PROCESSOR_MSG_HDR_END;
				}
				else
				{
					nxtChar = eol;
					httpMsg.setHttpData(eol);
					res = HTTP_PROCESSOR_MSG_HDR_INCOMPLETE;
				}
			}
			else
			{
				nxtChar = contentPtr;
				httpMsg.setHttpData(contentPtr);
				res = HTTP_PROCESSOR_MSG_HDR_INCOMPLETE;
			}
		}
		else
		{
			//Content header may not be included in the HDR
			endOfHdr = strstr(ptr, HTTP_END_OF_HDR);
			
			if (endOfHdr)
			{
				nxtChar = endOfHdr;
				res = HTTP_PROCESSOR_MSG_HDR_END;
			}
			else
			{
				nxtChar = ptr;
				httpMsg.setHttpData(ptr);
				res = HTTP_PROCESSOR_MSG_HDR_INCOMPLETE;
			}
		}
	}
	else
	{
		if (!(strlen(ptr) < strlen(methodEndpoint)))
		{
			res = HTTP_PROCESSOR_METHOD_ERR;
		}
		else
		{
			httpMsg.setHttpData(ptr);
			nxtChar = ptr;
			res = HTTP_PROCESSOR_MSG_HDR_INCOMPLETE;
		}
	}
	
	return res;
}
*/

/**********************************************************************************************************************
 * Name: processRestOfHTTPHdr
 * Description: This function is called for processing an HTTP header when the rest of the header data is received and
 * after calling processInitialHTTPHdr for first time. The header could be complete or still partial.
 *
 * Arguments:
 * char *	httpHdrData	Pointer to C String containing received header data
 * HTTPMsg&	httpMsg		HTTP msg being received and processed
 * char *&	nxtChar		out pointer to the next char to be processed. It will point to the edn of header chars
 *						if the header is complete.
 * int&		contentLen	Value of ContentLength header if it is found in the data received.
 * 
 * Returns
 * int 				result of HDR processing 
 *					HTTP_PROCESSOR_MSG_HDR_END
 *					HTTP_PROCESSOR_MSG_HDR_INCOMPLETE
 *					HTTP_PROCESSOR_CONTENT_LEN_ERR
 *					HTTP_PROCESSOR_METHOD_ERR
 *
 * Note:
 * httpHdrData must be NULL terminated C String.
 *********************************************************************************************************************/
/*
int HTTPProcessor::processRestOfHTTPHdr(char *httpHdrData, HTTPMsg &httpMsg, char *&nxtChar, const char *methodEndpoint, uint8_t methodEndPointLen)
{
	char *ptr = httpHdrData;
	char *contentPtr;
	char *methodPtr;
	char *auxPtr;
	char *endOfHdr;
	char *eol;
	int contentLen;
	
	httpMsg.setHttpData(ptr);

	ptr = (char *)httpMsg.getData();
	
	if (!httpMsg.getMethodFound())
	{
		methodPtr = strstr(ptr, methodEndpoint);
		
		if (methodPtr)
		{
			httpMsg.setMethodFound();
			ptr += methodEndPointLen;
		}
		else
		{
			if (!(strlen(ptr) < strlen(methodEndpoint)))
			{
				return HTTP_PROCESSOR_METHOD_ERR;
			}
			else
			{
				return HTTP_PROCESSOR_MSG_HDR_INCOMPLETE;
			}
		}
	} //else continue
	
	if (!httpMsg.getContentHdrFound())
	{
		contentPtr = strstr(ptr, HTTP_CONTENT_HDR);
		
		if (contentPtr)
		{
			eol = strstr(contentPtr, HTTP_END_OF_L);
			if (eol)
			{
				*eol = 0;
				httpMsg.setContentHdrFound();
				errno = 0;
				contentLen = strtol(contentPtr + HTTP_CONTENT_HDR_LEN, &auxPtr, 10);
				
				if (contentLen == 0)
				{
					if (!(*auxPtr == 0 && errno == 0))
					{
						return HTTP_PROCESSOR_CONTENT_LEN_ERR;
					}
				}
				
				httpMsg.setContentLen(contentLen);
				
				*eol = '\r';
				ptr = eol;
			}
			else
			{
				return HTTP_PROCESSOR_MSG_HDR_INCOMPLETE;
			}
		} //else continue - the message might not have content header
	}  //else continue
				
	endOfHdr = strstr(ptr, HTTP_END_OF_HDR);
	
	if (endOfHdr)
	{
		nxtChar = endOfHdr;
		return HTTP_PROCESSOR_MSG_HDR_END;
	}
	else
	{
		return HTTP_PROCESSOR_MSG_HDR_INCOMPLETE;
	}
}
*/
/**********************************************************************************************************************
 * Name: processHTTPBody
 * Description: This function processes HTTP body. If the body comes in different TCP messages, it will gather all 
 * chunks until body is completed. An error is returned if the body length is detected to be longer than Content Len.
 *
 * Arguments:
 * char *	httpBodyData	Pointer to C String containing received body data
 * HTTPMsg&	httpMsg			HTTP msg being received and processed
 * char *&	outBodyData		in/out pointer to the returned body data once the WHOLE and HEALTHY body was received
 * 
 * Returns
 * int 				result of body processing (COMPLETE, INCOMPLETE, ERROR)
 *
 * Note:
 * Body data received must be NULL terminated. Also outBodyData.
 * It is assumed body does not finish with '\r\n'
 *********************************************************************************************************************/
/*
int HTTPProcessor::processHTTPBody(char *httpBodyData, HTTPMsg& httpMsg, char *&outBodyData, bool initial)
{
	int bodyLen = strlen(httpBodyData) - HTTP_END_OF_HDR_LEN; //httpBodyData always begins with \r\n\r\n
	
	if (httpMsg.getBodyLen() == 0)
	{
		if (bodyLen == httpMsg.getContentLen())
		{
			outBodyData = httpBodyData + HTTP_END_OF_HDR_LEN;
			return HTTP_PROCESSOR_MSG_BODY_COMPLETE;
		}
		else
		{
			if (bodyLen < httpMsg.getContentLen())
			{
				if (initial)
				{
					httpMsg.setHttpData(httpBodyData);
				} //else already set
				
				return HTTP_PROCESSOR_MSG_BODY_INCOMPLETE;
			}
			else
			{
				return HTTP_PROCESSOR_MSG_BODY_EXTRALENGTH_ERROR;
			}
		}
	}
	else
	{
		//data already part of httpMsg because processRestOfHTTPHdr was called
		
		if (httpMsg.getBodyLen() == httpMsg.getContentLen())
		{
			outBodyData = httpMsg.getBodyData();
			return HTTP_PROCESSOR_MSG_BODY_COMPLETE;
		}
		else
		{
			if (httpMsg.getBodyLen() < httpMsg.getContentLen())
			{
				return HTTP_PROCESSOR_MSG_BODY_INCOMPLETE;
			}
			else
			{
				return HTTP_PROCESSOR_MSG_BODY_EXTRALENGTH_ERROR;
			}
		}
	}
}
*/
