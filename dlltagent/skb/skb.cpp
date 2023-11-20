#include <stdint.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <map>
#include <list>


#include "skb.h"
#include "binarytree_exp.h"
#include "daemonLog.h"

extern DaemonLog *daemonLogging;

#define MAX_SKB 1050000 //Greater than 0xFFFFF or 1,048,575
#define MAX_PROCESSING_DELETE_TASKS 50;

typedef struct skb_doublelink
{
    skb_t *usrSkb;
    struct skb_doublelink *next;
    struct skb_doublelink *prev;
} skb_doublelink_t;


typedef struct hash_skb
{
    bnode_t *root;
    pthread_mutex_t hash_skb_mutex;
} hash_skb_t;

skb_t *listConnectingSkb;
static pthread_mutex_t listConnectingSkbMutex;
skb_t *listEstablishedSkb;
static pthread_mutex_t listEstablishedSkbMutex;

static skb_t *headAvailableSkb = NULL;
static pthread_mutex_t headAvailableSkbMutex;
static hash_skb_t hashskb[MAX_SKB];
static skb_t gUsrSkb[MAX_SKB];
static int32_t lastSkbIdx = 0;

/* Counters */
static uint32_t reusedSkbCnt = 0;
static uint32_t newSkbCnt = 0;
static uint32_t unavailableSkbCnt = 0;
static uint32_t releasedSkbCount = 0;
static uint32_t submitDeleteSkbCnt = 0;


std::list<markedForDump_t> markedForDumpList;
std::map<skb_t *, std::list<markedForDump_t>::iterator> markedForDumpMap;
pthread_mutex_t markedForDumpMutex;


/**
 * Adds the given skb to the front of given list
 *
 * @param listSkb   list of skb's
 * @param newSkb    pointer to skb to be added
 */
static void addToListSkb(skb_t *&listSkb, skb_t *newSkb) {
    newSkb->next = listSkb;
    newSkb->prev = NULL;

    if (listSkb) {
        newSkb->next->prev = newSkb;
    }
    listSkb = newSkb;
}

/**
 * Removes skb from the given double-linked list
 *
 * @param listSkb   skb's double-linked list
 * @param skb       skb to remove
 */
static void removeFromListSkb(skb_t *&listSkb, skb_t *skb)
{
    //Remove from list of used skb's
    if (skb->prev) {
        skb->prev->next = skb->next;
    }
    else {
        listSkb = skb->next;
    }

    if (skb->next) {
        skb->next->prev = skb->prev;
    }
}

/**
 * This function adds deleted skb_t to the list of available SKB's pointed by headAvailableSkb (to the beginning).
 * headAvailableSkbMutex is locked to assure mutual exclusion with get_new_skb.
 *
 * @param skb_t*     to-be-released skb
 *
 */

static void delete_skb(skb_t *skb)
{
    skb->prev = NULL;
    skb->countFB = 0;
    skb->headFrameBuffer = NULL;
    skb->currFrameBuffer = NULL;
    pthread_mutex_lock(&headAvailableSkbMutex);
    if (headAvailableSkb) {
        skb->next = headAvailableSkb;
    }
    else {
        skb->next = NULL;
    }

    headAvailableSkb = skb;
    pthread_mutex_unlock(&headAvailableSkbMutex);
}


/**
 * Calcultes the key for auxSkb, this key, treekey, is used in the binary tree
 *
 * @param treekey   calaculated key
 * @param auxSkb    skb for which the key is calculated.
 */
static void getTreeKey(treekey_t *treekey, skb_t *auxSkb) {
    if ((*(uint32_t *)(auxSkb->ipSrc)) < (*(uint32_t *)(auxSkb->ipDst))) {
        treekey->treeIPKey = (int64_t)(*(uint32_t *)(auxSkb->ipSrc)) << 32 | (uint64_t)(*(uint32_t *)(auxSkb->ipDst));
        treekey->treePortKey = auxSkb->portSrc << 16 | auxSkb->portDst;
    } else {
        treekey->treeIPKey = (uint64_t)(*(uint32_t *)(auxSkb->ipDst)) << 32 | (uint64_t)(*(uint32_t *)(auxSkb->ipSrc));
        if ((*(uint32_t *)(auxSkb->ipSrc)) > (*(uint32_t *)(auxSkb->ipDst))) {
            treekey->treePortKey = auxSkb->portDst << 16 | auxSkb->portSrc;
        } else if (auxSkb->portSrc < auxSkb->portDst) {
            treekey->treePortKey = auxSkb->portSrc << 16 | auxSkb->portDst;
        } else {
            treekey->treePortKey = auxSkb->portDst << 16 | auxSkb->portSrc;
        }
    }
}


/**
 * Calculates the hash key in the hash of trees of hashkey
 *
 * @param hashkey       hashkey obtained
 * @param auxSkb        Auxiliary skb from which the hashkey is determined.
 */
static void getHashKey(uint32_t *hashkey, skb_t *auxSkb) {
    if (auxSkb->portSrc == 443 || auxSkb->portSrc == 8080 || auxSkb->portSrc == 80) {
        if (auxSkb->portDst != 443 && auxSkb->portDst != 8080 && auxSkb->portDst != 80) {
            *hashkey = (uint32_t) (auxSkb->portDst & 0xFFF) << 8 | (auxSkb->ipDst[3]);
        } else {
            if (auxSkb->portSrc < auxSkb->portDst) {
                *hashkey = (uint32_t) auxSkb->ipSrc[3] << 8 | (uint32_t) auxSkb->ipDst[3];
            } else if (auxSkb->portSrc > auxSkb->portDst) {
                *hashkey = (uint32_t) auxSkb->ipDst[3] << 8 | (uint32_t) auxSkb->ipSrc[3];
            } else {
                *hashkey = (uint32_t) auxSkb->portDst;
            }
        }
    } else if (auxSkb->portDst == 443 || auxSkb->portDst == 8080 || auxSkb->portDst == 80) {
        *hashkey = (uint32_t) (auxSkb->portSrc & 0xFFF) << 8 | (auxSkb->ipSrc[3]);
    } else if (auxSkb->portSrc < auxSkb->portDst) {
        *hashkey = (uint32_t) (auxSkb->portSrc & 0xFF) << 12 | (uint32_t) (auxSkb->portDst & 0xFF) << 4  | (auxSkb->ipSrc[3] & 0xF);
    } else if (auxSkb->portSrc > auxSkb->portDst) {
        *hashkey = (uint32_t) (auxSkb->portDst & 0xFF) << 12 | (uint32_t) (auxSkb->portSrc & 0xFF) << 4  | (auxSkb->ipDst[3] & 0xF);
    } else {
        *hashkey = (uint32_t) auxSkb->portDst;
    }
}


/**
 * Deletes the skb's node from the binary tree
 *
 * @param auxSkb    skb to remove.
 *
 */
static void deleteSkbFromBinaryTree(skb_t *auxSkb)
{
    uint32_t hashkey;
    treekey_t treekey;

    getHashKey(&hashkey, auxSkb);
    getTreeKey(&treekey, auxSkb);
    pthread_mutex_lock(&hashskb[hashkey].hash_skb_mutex);

    if (hashskb[hashkey].root != NULL)
    {
        deletenode(&treekey, &(hashskb[hashkey].root));
        SET_SKB_KILLED_DELETED(auxSkb);
    } //NULL

    pthread_mutex_unlock(&hashskb[hashkey].hash_skb_mutex);

}

/**
 * Explanation1: race condition avoidance while deleting a skb.
 * ============================================================
 *
 * submitDeleteSpecificListSkb is in charge of deleting an skb and making it available for a new connection.
 * It does all housekeeping: removes it form the binary tree, removes it from the lists referencing it, makes it available in
 * headAvailableSkb.
 * It must assure it doesn't make available a skb that is being used by another thread. This is achieved by:
 * First, the skb is removed from the binary tree, so future threads won't be able to find it anymore.
 * The function that can find the skb in the binary tree is skbLookup. Access to the binary tree is done with mutual exclusion and while
 * the locker is taken, skbLookup increases skb->used. Then submitDeleteSpecificListSkb will not make the skb available if skb->used is GT 0.
 *
 * In skbLookup, skb->used is incremented while holding the binary-tree's mutex. Thus, we cannot ave a sequence in which skb is found in tree
 * by skbLookup, then removed from tree by submitDeleteSpecificListSkb, then ask if skb->used EQ 0 in submitDeleteSpecificListSkb and then
 * skbLookup increments skb->used. skbLookup finds the skb and increments skb->used atomically. submitDeleteSpecificListSkb can remove the skb
 * from tree either before or after:
 * -Before: skbLookup will not find it. That's it.
 * -After: skb->used is GT 0 and it is not made available. Eventually the thread returns skb. Since the skb remains in the same list,
 *         next time it will be found and submitDeleteSpecificListSkb called again.
 *
 *
 */



/**
 * This function deletes an skb from that is removed from the pased list listSkb.
 * First, the skb_t's corresponding node in the corresponding btree is deleted by calling deleteSkbFromBinaryTree
 * Then, if no other thread is using this skb, it will remove it from the listSkb and then deleted by
 * calling delete_skb which will make the skb available by adding it to headAvailableSkb.
 * If the skb is being used by another thread, processedSkb->used will be GT 0 and this function needs
 * to be called again later. The good thing is that the skb was already removed from the tree, so nobody
 * else can grab it.
 * Read Explanation1 for how race condition is avoided.
 *
 * @param listSkb       list from which the skb will be removed
 * @param listMutex     list's mutex
 * @param processedSkb  skb to be deleted
 * @return 0 if skb is being used and cannot be completely deleted and 1 if it was completely deleted.
 *
 * @Caution: we cannot remove the skb from the list if skb->used GT 0, because it will be the only reference we have to this skb.
 *           This assures it can be completely deleted and made available later.
 *
 */
static int submitDeleteSpecificListSkb(skb_t *&listSkb, pthread_mutex_t& listMutex, skb_t *processedSkb) {
    int res = 1;
    //printf("submitDeleteSpecificListSkb: %1.1d.%1.1d.%1.1d.%1.1d:%u - %1.1d.%1.1d.%1.1d.%1.1d:%u\n", processedSkb->ipSrc[0], processedSkb->ipSrc[1], processedSkb->ipSrc[2], processedSkb->ipSrc[3], processedSkb->portSrc,
    //        processedSkb->ipDst[0], processedSkb->ipDst[1], processedSkb->ipDst[2], processedSkb->ipDst[3], processedSkb->portDst);
    if (!IS_SKB_KILLED_DELETED(processedSkb)) {
        deleteSkbFromBinaryTree(processedSkb);
    }
    if (processedSkb->used == 0) {
        pthread_mutex_lock(&listMutex);
        removeFromListSkb(listSkb, processedSkb);
        pthread_mutex_unlock(&listMutex);
        delete_skb(processedSkb);
    } else {
        res = 0;
        daemonLogging->debug("Another thread is using the skb, cannot delete\n");
    }
    return res;
}

/**
 * This function resets internal data and calls releaseAllBinaryTreeMemory
 * It also checks some pointers have the proper value for correctness. If not a message is logged, they mean
 * there is some memory leak error somewhere.
 *
 */
void shutdownSkb() {
    for(int j = 0; j < MAX_SKB; j++) {
        if (hashskb[j].root != NULL) {
            daemonLogging->error("root %d is not NULL\n", j);
        }
    }
    if (listConnectingSkb != NULL) {
        daemonLogging->error("listConnectingSkb is not NULL\n");
    }
    if (listEstablishedSkb != NULL) {
        daemonLogging->error("listEstablishedSkb is not NULL\n");
    }
    if (headAvailableSkb == NULL) {
        daemonLogging->error("headAvailableSkb is NULL\n");
    }
    headAvailableSkb = NULL;
    lastSkbIdx = 0;
    releaseAllBinaryTreeMemory();
}


/**
 * This function must be always called before using skb's
 * It initializes all data and binary tree by calling init_binary_tree
 *
 */
void initializeSkb()
{
    int j;
    int res;

    pthread_mutex_init(&listConnectingSkbMutex, NULL);
    pthread_mutex_init(&listEstablishedSkbMutex, NULL);
    pthread_mutex_init(&headAvailableSkbMutex, NULL);
    pthread_mutex_init(&markedForDumpMutex, NULL);

    for(j=0; j < MAX_SKB; j++)
    {
        pthread_mutex_init(&(gUsrSkb[j].skbmutex), NULL);
        hashskb[j].root = NULL;
        //pthread_mutex_init(&(hashskb[j].hash_skb_mutex), NULL);
    }

    res = init_binary_tree();
    if (res < 0)
    {
           daemonLogging->error("CRITICAL error initializing binary tree\n");
        exit(2);
    }

    listConnectingSkb = NULL;
    listEstablishedSkb = NULL;
    headAvailableSkb = NULL;
    
    reusedSkbCnt = 0;
    newSkbCnt = 0;
    unavailableSkbCnt = 0;
}


/**
 * Logs statistical data
 *
 */
void logSkbManagementData()
{
    daemonLogging->info("RETRIEVED SKBs:\nNEW SKBs: %lu\nREUSEDs SKBs: %lu\nUNAVAILABLE SKBs: %lu\n", newSkbCnt, reusedSkbCnt, unavailableSkbCnt);
    daemonLogging->info("RELEASED SKBs:\nSUBMITTED SKB's: %lu\nRELEASED SKB's: %lu\n", submitDeleteSkbCnt, releasedSkbCount);
}


/**
 * Retrieves a new skb. The skb can be reused from a previously killed skb or, if none to be reused,
 * it can be obtained from the global array of skb, gUsrSkb, the next available one pointed to by index lastSkbIdx.
 * the retreived skb is zeroed and the registeredSequence set to 0xFFFFFFFF (invalidated).
 *
 * @return  skb_t *  valid if there is an available skb.
 *                   NULL if there is no skb left (which should be a problem situation)
 *
 */

skb_t *get_new_skb()
{
    skb_t *newskb;

    pthread_mutex_lock(&headAvailableSkbMutex);
    if (headAvailableSkb)
    {
        newskb = headAvailableSkb;
        headAvailableSkb = headAvailableSkb->next;
        reusedSkbCnt++;
    }
    else
    {
        if (lastSkbIdx < MAX_SKB)
        {
            newskb = &gUsrSkb[lastSkbIdx++];
            newSkbCnt++;
        }
        else
        {
            newskb = NULL;
            unavailableSkbCnt++;
        }
    }
    pthread_mutex_unlock(&headAvailableSkbMutex);

    if (newskb != NULL)
    {
        bzero((void *)newskb, sizeof(skb_t));
        newskb->registeredSequence = 0xFFFFFFFF;
    }

    return newskb;
}


/**
 * This function receives a pointer to a brand new skb_t and will add it in the
 * corresponding entry in te hash of skb's (hashskb).
 * Every hash entry contains a binary tree.
 * If it's the first skb_t for that entry, it initializes the tree root. The skb_t
 * is inserted into the tree.
 * Then the new skb_t is added to the beginning of the list of connecting skb's, listConnectingSkb.
 *
 * @param newSkb  a new skb to add into the corresponding binary tree depending on its hash key.
 *
 * @return 0 if success, -1 on error adding the skb's node to the binary tree.
 *
 */

int addNewSkb(skb_t *newSkb)
{
    int res;
    uint32_t hashkey;
    treekey_t treekey;
    
    getHashKey(&hashkey, newSkb);
    getTreeKey(&treekey, newSkb);

    pthread_mutex_lock(&hashskb[hashkey].hash_skb_mutex);
    //printf("VALUE HASH: %X - %u - %d\n", hashkey, hashkey, hashkey < MAX_SKB);
    if (hashskb[hashkey].root != NULL)
    {
        //printf("SEARCH NODE: %lu\n", (unsigned long)((hashskb[hashkey].root)->key));
        if (searchnode(&treekey, hashskb[hashkey].root) == NULL)
        {
            //printf("ADD NODE: %lu\n", (unsigned long)((hashskb[hashkey].root)->key));
            addnode(&treekey, (datatype)newSkb, &(hashskb[hashkey].root));
        } 
        else //else it's already there
        {
            daemonLogging->error("WEIRD SITUATION: hashkey %lu : %u is already there\n", (long unsigned int)treekey.treeIPKey, treekey.treePortKey);
        }
    }
    else
    {
        res = init_root(&(hashskb[hashkey].root), &treekey, (datatype) newSkb);
        if (res < 0)
        {
            pthread_mutex_unlock(&hashskb[hashkey].hash_skb_mutex);
            daemonLogging->error("CRITICAL error initializing root node\n");
            return -1;;
        }
        else
        {
            hashskb[hashkey].root->key.treeIPKey = treekey.treeIPKey;
            hashskb[hashkey].root->key.treePortKey = treekey.treePortKey;
            hashskb[hashkey].root->data = (datatype) newSkb;
        }
    }
    pthread_mutex_unlock(&hashskb[hashkey].hash_skb_mutex);

    pthread_mutex_lock(&listConnectingSkbMutex);
    newSkb->next = listConnectingSkb;
    newSkb->prev = NULL;

    if (listConnectingSkb) {
        newSkb->next->prev = newSkb;
    }
    listConnectingSkb = newSkb;

    pthread_mutex_unlock(&listConnectingSkbMutex);
    
    return 0;
}

/**
 * Delete the passed skb and remove it from the connecting list
 *
 * @param processedSkb  skb to be deleted
 * @return      0 if skb is being used and cannot be completely deleted, submitDeleteConnectingSkb will need to be called again later.
 *              1 if it was completely deleted.
 */
int submitDeleteConnectingSkb(skb_t *processedSkb) {
    return submitDeleteSpecificListSkb(listConnectingSkb, listConnectingSkbMutex, processedSkb);
}

/**
 * Delete the passed skb and remove it from the connection-established list
 *
 * @param processedSkb  skb to be deleted
 * @return      0 if skb is being used and cannot be completely deleted, submitDeleteEstablishedSkb will need to be called again later.
 *              1 if it was completely deleted.
 */
int submitDeleteEstablishedSkb(skb_t *processedSkb) {
    return submitDeleteSpecificListSkb(listEstablishedSkb, listEstablishedSkbMutex, processedSkb);
}

/**
 * Adds skb to list of established connections
 *
 * @param skb   pointer to skb_t to add
 */
static void addToEstablishedListSkb(skb_t *skb) {
    //No need to lock as long as only one thread accesses it
    addToListSkb(listEstablishedSkb, skb);
}

/**
 * Removes the processedSkb from the listConnectingSkb and adds it to the listEstablishedSkb
 *
 * @param processedSkb  pointer to skb to be moved
 */
void moveSkbToEstablishedQ(skb_t *processedSkb) {
    pthread_mutex_lock(&listConnectingSkbMutex);
    removeFromListSkb(listConnectingSkb, processedSkb);
    pthread_mutex_unlock(&listConnectingSkbMutex);
    addToEstablishedListSkb(processedSkb);
}


/**
 * One skb_t is processed always by the same thread. So there is not other thread using this skb_t while
 * skbLookup is called by this thread.
 * The only thread that can try to access this thread is the one processing queues.
 * This list processing thread will use the same lock before deleting this skb_t.
 * Note that we lock the binary tree's mutex  before searching the skb and, with the mutex locked skbPtr->used
 * is incremented. This assures the skb will not be made available if at the same time queue-processing thread decides
 * to delete the skb.
 *
 * @param auxSkb    skb ptr with the data to determine the key and search in the binary tree.
 * @return  the found skb or NULL.
 */
skb_t *skbLookup(skb_t *auxSkb)
{
    uint32_t hashkey;
    treekey_t treekey;
    bnode_t *node = NULL;
    
    getHashKey(&hashkey, auxSkb);
    pthread_mutex_lock(&hashskb[hashkey].hash_skb_mutex);

    if (hashskb[hashkey].root != NULL)
    {
        getTreeKey(&treekey, auxSkb);

        node = searchnode(&treekey, hashskb[hashkey].root);
        if (node != NULL)
        {
            skb_t *skbPtr = (skb_t *)(node->data);
            skbPtr->used++;
            pthread_mutex_unlock(&hashskb[hashkey].hash_skb_mutex);
            return skbPtr;
        } //NULL
    } //NULL

    pthread_mutex_unlock(&hashskb[hashkey].hash_skb_mutex);
    return NULL;
}



void addMarkedForDump(skb_t *skb) {
    pthread_mutex_lock(&markedForDumpMutex);
    markedForDump_t dumpData;
    dumpData.skb = skb;
    getTimestampNow(dumpData.timeMarked);
    markedForDumpList.push_back(dumpData);
    markedForDumpMap[skb] = std::prev(markedForDumpList.end());
    pthread_mutex_unlock(&markedForDumpMutex);
}

void removeMarkedForDump(skb_t *skb) {
    pthread_mutex_lock(&markedForDumpMutex);
    auto iter = markedForDumpMap.find(skb);
    if (iter != markedForDumpMap.end()) {
        markedForDumpList.erase(iter->second);
        markedForDumpMap.erase(iter);
    }
    pthread_mutex_unlock(&markedForDumpMutex);
}

skb_t *processDumpRequired(uint16_t seconds) {
    pthread_mutex_lock(&markedForDumpMutex);
    skb_t *retSkb = nullptr;
    auto iter = markedForDumpList.begin();
    if (iter != markedForDumpList.end()) {
        struct timeval timeNow;
        getTimestampNow(timeNow);
        if (timeNow.tv_sec - iter->timeMarked.tv_sec > seconds) {
            retSkb = iter->skb;
            markedForDumpList.erase(iter);
            markedForDumpMap.erase(retSkb);
        }
    }
    pthread_mutex_unlock(&markedForDumpMutex);
    return retSkb;
}

void cleanMarkedForDump() {
    pthread_mutex_lock(&markedForDumpMutex);
    auto iter = markedForDumpList.begin();
    while (iter != markedForDumpList.end()) {
        skb_t *retSkb = iter->skb;
        markedForDumpList.erase(iter);
        markedForDumpMap.erase(retSkb);
        iter = markedForDumpList.begin();
    }
    pthread_mutex_unlock(&markedForDumpMutex);
}

//1,000,000
#define USEC_IN_SEC 1000000
#define TEN_HS_SEC 3600

/**
 * Calculate latency comparing with initialTime. We expect initialTime is set to when the first SYN msg was seen.
 * Latency is calculated when we see SYN-ACK and last-handshake ACK.
 * Latency is stored in an uint32_t datatype (usrSkb->latency) because that is enough to store hours
 * of latency. I don't expect a latency of more than 1 hour :)
 * NOTE: latency is set in usec!
 *
 * @param usrSkb    socket buffer
 * @param lastTime  time for the latest msg we are considering for determining latency. Format is
 *                  (tv_sec, tv_usec)
 */
void calcLatency(skb_t *usrSkb, struct timeval *lastTime) {
    __suseconds_t usecs;
    __time_t secs = lastTime->tv_sec - usrSkb->initialTime.tv_sec;
    if (usrSkb->initialTime.tv_usec > lastTime->tv_usec) {
        secs--;
        usecs = USEC_IN_SEC - usrSkb->initialTime.tv_usec + lastTime->tv_usec;
    } else {
        usecs = lastTime->tv_usec - usrSkb->initialTime.tv_usec;
    }
    if (secs > TEN_HS_SEC) {
        daemonLogging->error("Number of latency seconds is greater than 1 hr: %u - for: %u - %u - %X - %X",
                secs, usrSkb->portSrc, usrSkb->portDst,
                *((uint32_t *)(usrSkb->ipSrc)), *((uint32_t *)(usrSkb->ipDst)));
    } else {
        if (usrSkb->cStatus == SYN_ACK) {
            usrSkb->latency1 = (uint32_t)(secs * USEC_IN_SEC + usecs); //SYNACK received or sent
        } else if (usrSkb->cStatus == LAST_HSHAKE_ACK) {
            usrSkb->latency2 = (uint32_t)(secs * USEC_IN_SEC + usecs) - usrSkb->latency1; //Final 3-way-handshake's ACK received or sent
        } else {
            usrSkb->latency3 = (uint32_t)(secs * USEC_IN_SEC + usecs) - usrSkb->latency2; //In TLS, handshake complete
        }
    }
}


