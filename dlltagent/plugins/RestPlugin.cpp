/*
 * RestPlugin.cpp
 *
 *  Created on: Mar 26, 2020
 *      Author: rodolk
 */

#include "RestPlugin.h"

#include <memory>

#include <curl/curl.h>
#include <string.h>


extern "C" {
std::shared_ptr<plugins::IRestPlugin> createRestPlugin(const std::string& uri,
        const bool tlsOption,
        const bool tlsIgnoreSrvCertOption,
        const std::string& questionResource);
}
std::shared_ptr<plugins::IRestPlugin> createRestPlugin(const std::string& uri,
        const bool tlsOption,
        const bool tlsIgnoreSrvCertOption,
        const std::string& questionResource) {
    return std::make_shared<plugins::RestPlugin>(uri, tlsOption, tlsIgnoreSrvCertOption, questionResource);
}

namespace plugins {

RestPlugin::~RestPlugin() {
    // TODO Auto-generated destructor stub
}

typedef struct curlHTTPMsg {
  const char *readptr;
  size_t sizeleft;
} curlHTTPMsg_t;

size_t RestPlugin::read_callback(void *dest, size_t size, size_t nmemb, void *userp)
{
    curlHTTPMsg_t *curlMsg = (curlHTTPMsg_t *)userp;
    size_t buffer_size = size*nmemb;

    if(curlMsg->sizeleft) {
        /* copy as much as possible from the source to the destination */
        size_t copy_this_much = curlMsg->sizeleft;
        if(copy_this_much > buffer_size) {
            copy_this_much = buffer_size;
        }
        memcpy(dest, curlMsg->readptr, copy_this_much);

        curlMsg->readptr += copy_this_much;
        curlMsg->sizeleft -= copy_this_much;
        return copy_this_much; /* we copied this many bytes */
    }

    return 0;
}


void RestPlugin::sendData(string resource, const char *msg, uint16_t len) {
    CURL *curl;
    CURLcode res;
    curlHTTPMsg_t curlMsg;

    curlMsg.readptr = msg;
    curlMsg.sizeleft = len;

    logging_->debug("Send msg: %s\n", msg);

    /* In windows, this will init the winsock stuff */
    res = curl_global_init(CURL_GLOBAL_DEFAULT);
    if(res != CURLE_OK) {
        logging_->error("curl_global_init() failed: %s\n", curl_easy_strerror(res));
        return;
    }

    /* get a curl handle */
    curl = curl_easy_init();
    if(curl) {
        struct curl_slist *headers=NULL;
        /* First set the URL that is about to receive our POST. This URL can
           just as well be a https:// URL if that is what should receive the
           data. */
        string uriResult = uri_ + resource;
        curl_easy_setopt(curl, CURLOPT_URL, uriResult.c_str());
        /* Now specify the POST data */
        //curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "name=daniel&project=curl");

        curl_easy_setopt(curl, CURLOPT_POST, 1L);

        curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);

        curl_easy_setopt(curl, CURLOPT_READDATA, &curlMsg);

        if (logging_->isDebugEnabled()) {
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        } else {
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);
        }
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, "Accept: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        /* Set the expected POST size. If you want to POST large amounts of data,
           consider CURLOPT_POSTFIELDSIZE_LARGE */
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)curlMsg.sizeleft);

        if (tlsOption_) {
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, (tlsIgnoreSrvCertOption_ ? 0L : 1L));
        }

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            logging_->error("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }
        /* always cleanup */
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    }
    curl_global_cleanup();
}





// ////////////////////////////////////////



std::size_t RestPlugin::getNewCommandCallback(const char *ptr, size_t size, size_t nmemb, void *userdata) {

    size_t realsize = size * nmemb;
    requestData_t *req = (requestData_t *) userdata;

    while (req->buflen < req->len + realsize + 1) {
        req->buffer = (uint8_t *)realloc(req->buffer, req->buflen + CHUNK_SIZE);
        req->buflen += CHUNK_SIZE;
    }
    memcpy(&req->buffer[req->len], ptr, realsize);
    req->len += realsize;
    req->buffer[req->len] = 0;

    return realsize;
}

#define HEAD_BEGIN "<head>"
#define HEAD_END "</head>"

#define BODY_BEGIN "<body>"
#define BODY_END "</body>"

#define BODY_BEGIN_LEN 6



void RestPlugin::processHTTPMessage(requestData_t& reqData, char *& offset, uint32_t& messageLen) {
    char *headPtr = strstr((char *)reqData.buffer, HEAD_BEGIN);
    offset = nullptr;
    messageLen = 0;
    if (headPtr != NULL) {
        char *headEndPtr = strstr(headPtr, HEAD_END);
        if (headEndPtr != NULL) {
            char *bodyPtr = strstr(headPtr, BODY_BEGIN);
            if (bodyPtr != NULL) {
                char *bodyEndPtr = strstr(headPtr, BODY_END);
                if (bodyEndPtr != NULL) {
                    offset = bodyPtr + BODY_BEGIN_LEN;
                    messageLen = bodyEndPtr - offset;
                }
            }
        }
    }

    if (!offset) {
        offset = (char *)reqData.buffer;
        messageLen = reqData.len;
    }
}


// URL:
// https://a72c3e2msk.execute-api.us-west-2.amazonaws.com/Prod/facts/a1/questions

//TODO: avoid multi-threading

int RestPlugin::getNewCommand(requestData_t *reqData, char *& offset, uint32_t& messageLen) {
    CURL *curl;
    CURLcode res;
    int httpCode;
    int result = 0;

    logging_->info("URI: %s\n", uri_);

    /* In windows, this will init the winsock stuff */
    res = curl_global_init(CURL_GLOBAL_DEFAULT);
    if(res != CURLE_OK) {
        logging_->error("curl_global_init() failed: %s\n", curl_easy_strerror(res));
        return -1;
    }

    curl = curl_easy_init();
    if(curl) {
        struct curl_slist *headers=NULL;
        string uriResult = uri_ + questionResource_;
        curl_easy_setopt(curl, CURLOPT_URL, uriResult.c_str());

        logging_->info("URI RESULT: %s\n", uriResult);
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
        //Wait a maximum time of 30 seconds to receive the response
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, maxTimeout_);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, getNewCommandCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, reqData);

        if (logging_->isDebugEnabled()) {
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        } else {
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);
        }
        headers = curl_slist_append(headers, "Accept: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        if (tlsOption_) {
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, (tlsIgnoreSrvCertOption_ ? 0L : 1L));
        }

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            logging_->error("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            result = -1;
        } else {
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
            if (httpCode != 200) {
                result = httpCode;
            } else {
                logging_->debug("MESSAGE: %s\n", reqData->buffer);
                logging_->debug("------------------------------");
                processHTTPMessage(*reqData, offset, messageLen);
            }
        }

        /* always cleanup */
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    }
    curl_global_cleanup();

    return result;
}


} //namespace plugins
















