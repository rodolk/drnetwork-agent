#ifndef QUEUE_H
#define QUEUE_H

#include <stdlib.h>
#include <stdio.h>

#define NUM_ELEM 2
#define NUM_POSITIONS NUM_ELEM + 1

using namespace std;

template<class ElemType> class Queue;
/*
template<class ElemType> ostream& operator<<(ostream& stream, const Queue<ElemType>& queue)
{
    int nextElem;
    int init = queue.consIdx;
    int end = queue.prodIdx;
    
    ios_base::fmtflags flags = stream.flags();
    stream.setf(ios_base::hex, ios_base::basefield);
    
    stream << "DATA IN QUEUE:" << endl;
    
    for(nextElem = init; nextElem != end; nextElem = (nextElem + 1) % NUM_POSITIONS)
    {
        stream << *queue.buffer[nextElem] << endl;
    }
    
    stream << endl;
    
    stream.flags(flags);
    
    return stream;
}
*/
template<class ElemType> class Queue
{
    volatile unsigned int prodIdx;
    volatile unsigned int consIdx;
    ElemType** buffer;
    int numPositions;
    
    public:
        
        enum eQueueStatus {QUEUE_FULL = -1, QUEUE_OK = 0};
        
        void createBuffer(int numElements)
        {
            buffer = (ElemType **) malloc((numElements + 1) * sizeof(ElemType *));
            if (!buffer)
            {
                fprintf(stderr, "Error allocating queue buffer\n");
            }
            numPositions = numElements + 1;
        }
        
        Queue():prodIdx(0), consIdx(0)
        {
            createBuffer(NUM_ELEM);
        }
        
        Queue(int numElements):prodIdx(0), consIdx(0)
        {
            createBuffer(numElements);
        }
        
        eQueueStatus addElement(ElemType *);
        
        ElemType *getNextElement();
 
    //friend ostream& operator<< <ElemType> (ostream& stream, const Queue<ElemType>& queue);
};
        




template<class ElemType> typename Queue<ElemType>::eQueueStatus Queue<ElemType>::addElement(ElemType *elem)
{
    typename Queue<ElemType>::eQueueStatus result = QUEUE_OK;
    
    unsigned int volatile nextPosition = (prodIdx + 1) % numPositions;
    
    
    if (nextPosition == consIdx)
    {
        result = QUEUE_FULL;
    }
    else
    {
        buffer[prodIdx] = elem;
        prodIdx = nextPosition;
    }
    
    return result;
}



template<class ElemType> ElemType *Queue<ElemType>::getNextElement()
{
    ElemType *elemResult = NULL;
    unsigned int auxVal = (consIdx + 1) % numPositions;
    
    if (consIdx != prodIdx)
    {
        elemResult = buffer[consIdx];
        consIdx = auxVal;
    }
    
    return elemResult;
}
#endif
