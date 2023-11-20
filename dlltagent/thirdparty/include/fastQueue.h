/*
 * FastQueue.h
 *
 *  Created on: Apr 2, 2021
 *      Author: rodolk
 */

#ifndef FASTQUEUE_H_
#define FASTQUEUE_H_

#include <iostream>
#include <mutex>
#include <condition_variable>
#include <chrono>

#include "memoryManager.h"

template <class T> class FastQueue {
public:
    FastQueue(uint32_t initial, uint32_t increm, uint32_t maxIncrem, bool foreground = false) :
        initialSize_(initial), incremThreshold_(increm), maxIncrem_(maxIncrem), fg_(foreground) {
        mMgrLinks_ = new objmem_manager::MemoryManager<Link, LINK_STR>(initial, increm, maxIncrem);
    }

    virtual ~FastQueue() {
        clean();
        delete mMgrLinks_;
    }

    void clean() {
        std::unique_lock<std::mutex> lock(qMutex_);
        Link *link = head_;
        int count = 0;
        while (link != nullptr) {
            count++;
            Link *nextLink = link->next;
            if (link->object != nullptr) {
                delete link->object;
            }
            mMgrLinks_->returnInstance(link);
            link = nextLink;
        }
        length_ = 0;
        head_ = nullptr;
    }

    bool push(T *elem) {
        std::unique_lock<std::mutex> lock(qMutex_);
        try {
            Link *link = mMgrLinks_->createInstance();
            link->next = head_;
            link->previous = nullptr;
            if (head_) {
                link->next->previous = link;
            } else {
                tail_ = link;
            }
            head_ = link;
            link->object = elem;
            length_++;
            if (length_ == initialSize_ && lastReport_ < initialSize_) {
                if (fg_)
                    std::cerr << "Warning: length reached initial threshold." << std::endl;
                lastReport_ = initialSize_;
                warningStatus_ = 1;
            }
            emptyQCV_.notify_all();
            return true;
        } catch(typename objmem_manager::MemoryManager<Link, LINK_STR>::MemoryMgrException& excep) {
            if (fg_) {
                std::cerr << excep.what() << std::endl;
                std::cerr << "Error FastQueue: Could not create instance of Link in MemoryManager" << std::endl;
            }
            return false;
        }
    }

    T *pop(std::chrono::milliseconds timeMs = 10000ms) {
        std::unique_lock<std::mutex> lock(qMutex_);

        if (timeMs == 0ms) {
            while (tail_ == nullptr) emptyQCV_.wait(lock);
        } else {
            if (tail_ == nullptr) {
                emptyQCV_.wait_for(lock, timeMs);
                if (tail_ == nullptr) return nullptr;
            }
        }
        Link *link = tail_;
        tail_ = tail_->previous;
        if (tail_) {
            tail_->next = nullptr;
        } else {
            head_ = nullptr;
        }
        T *tptr = link->object;
        mMgrLinks_->returnInstance(link);
        length_--;
        if (length_ == ((initialSize_ * 6) / 10)) {
            lastReport_ = 0;
            warningStatus_ = 0;
        }
        return tptr;
    }

    uint32_t getLength() const {return length_;}
    uint8_t getWarningStatus() const {return warningStatus_;}

private:
    struct Link {
        T *object;
        Link *previous;
        Link *next;
    };
    static constexpr const char LINK_STR[] = "Link";
    objmem_manager::MemoryManager<Link, LINK_STR> *mMgrLinks_;
    std::mutex qMutex_;
    std::condition_variable emptyQCV_;
    Link *head_{nullptr};
    Link *tail_{nullptr};
    uint32_t length_{0};
    uint32_t lastReport_{0};
    uint32_t initialSize_{0};
    uint32_t incremThreshold_{0};
    uint32_t maxIncrem_{0};
    uint8_t warningStatus_{0};
    bool fg_{false};
};

#endif /* FASTQUEUE_H_ */
