/*
 * skbUnitTest.cpp
 *
 *  Created on: Oct 14, 2020
 *      Author: rodolk
 */

#include <arpa/inet.h>
#include <stdint.h>
#include <iostream>
#include <gtest/gtest.h>

#include "skb.h"

#include "skbValues.h"


int processSkb(skb_t& auxSkb) {

    skb_t *usrSkbfound;
    skb_t *currSkb;

    usrSkbfound = skbLookup(&auxSkb);
    if (usrSkbfound == NULL)
    {
        currSkb = get_new_skb();

        if (currSkb)
        {
            memcpy((void *)currSkb, (void *)&auxSkb, SIZE_OF_IP_PORT);

            /*
             * After we insert the new skb_t calling addNewSkb, the skb_t can be processed in function processNxtSkbList.
             * So skb_t must be configured before adding it.
             * No need to synchronize access until the new skb is added to the list of used skb_t's.
             */
            currSkb->cStatus = SYN;

            //RESET_SKB_VALID_CNT(currSkb);
            //RESET_SKB_STATE_VALID(currSkb);
            RESET_STATE(currSkb);
            currSkb->syncRetries = 0;
            currSkb->initialTime.tv_sec = 0;
            currSkb->initialTime.tv_usec = 0;
            currSkb->origPortSrc = currSkb->portSrc;
            currSkb->origPortDst = currSkb->portDst;
            memcpy(currSkb->origIpSrc, currSkb->ipSrc, IPV4_ADDR_LEN);

            addNewSkb(currSkb);

            return 1;
        } else {
            return -1;
        }
    } else {
        return 2;
    }
}

using namespace std;

void testSkb1() {
    skb_t auxSkb;
    struct in_addr ipAddr;
    unsigned int i;

    for(i = 0; i < (sizeof(srcIPArr) / 8); i++) {
        auxSkb.portSrc = srcPortArr[i];
        auxSkb.portDst = dstPortArr[i];

        inet_pton(AF_INET, srcIPArr[i], &ipAddr);
        memcpy(auxSkb.ipSrc, &ipAddr, 4);

        inet_pton(AF_INET, dstIPArr[i], &ipAddr);
        memcpy(auxSkb.ipDst, &ipAddr, 4);

        int res = processSkb(auxSkb);
        cout << "STEP: " << i << " res: " << res << endl;
        ASSERT_TRUE(res == resultArr[i]);

    }

}
