/*
 * MemoryManager.h
 *
 *  Created on: Mar 30, 2021
 *      Author: rodolk
 */

#ifndef MEMORYMANAGER_H_
#define MEMORYMANAGER_H_

#include <mutex>
#include <cstdint>
#include <cstdlib>
#include <sstream>
#include <iostream>
#include <exception>

namespace objmem_manager {

#define MAX_OBJETS_INCREMENTS 3

template <typename T, char const *typePrettyName> class MemoryManager {
public:
    class MemoryMgrException : public std::exception {
    public:
        MemoryMgrException(uint8_t code = 0, std::string msg = "") : code_(code) {
            std::stringstream sstr;
            sstr << "Memory manager exception for typename " << std::string(typeid(T).name()) << ", " << std::string(typePrettyName) << ", code: ";
            sstr << (unsigned int) code_;
            sstr << ", msg: " << msg;

            exceptionMsg_ = sstr.str();
        }

        std::string getExceptionMsg() {return exceptionMsg_;}

        uint8_t getCode() {return code_;}
    protected:
        uint8_t code_;
        std::string exceptionMsg_;
    };

    MemoryManager<T, typePrettyName>(uint32_t numInstances) {
        if (numInstances > 0) initialize(numInstances);
        else throw MemoryMgrException(1, "Num instances must be gt 0");
    }

    MemoryManager<T, typePrettyName>(uint32_t numInstances, uint32_t increment, uint32_t maxIncrement) {
        if (numInstances > 0 && increment > 0) {
            initialize(numInstances, increment, maxIncrement);
        } else throw MemoryMgrException(2, "Num instances and increment must be gt 0");
    }

    virtual ~MemoryManager<T, typePrettyName>() {
        if (usedObjects_ > 0) {
            std::cerr << "There are leaked objects in MemoryManager for " << typeid(T).name() << std::endl;
        }
        destroyEverything();
    }

    void activateTimeControl() {

    }

    T *createInstance() {
        std::unique_lock<std::mutex> lock(listMutex_);

        if (headAvailable_) {
            return useFirstAvailableObject();
        } else {
            if (totIncrements_ < maxIncrement_) {
                bool res = allocateMemForInstances(increment_, totIncrements_ + 1);
                if (!res) {
                    throw MemoryMgrException(3, "Error incrementing instances in MemoryManager");
                }
                std::cerr << "Warning: increment " << (totIncrements_ + 1) << " out of " << maxIncrement_
                        << " in MemoryManager for type " << typeid(T).name() << std::endl;
                headAvailable_ = &incrementsLinkArray_[totIncrements_ + 1][0]; //TODO: check everything
                totIncrements_++;
                return useFirstAvailableObject();
            } else {
                throw MemoryMgrException(4, "No more instances available");
            }
        }
    }

    void returnInstance(T *retInstance) {
        std::unique_lock<std::mutex> lock(listMutex_);

        if (headAvailableLink_) {
            MMLink *instLink = headAvailableLink_;
            headAvailableLink_ = headAvailableLink_->next_;
            instLink->next_ = headAvailable_;
            headAvailable_ = instLink;
            instLink->object_ = retInstance;
            usedObjects_--;
            return ;
        } else {
            throw MemoryMgrException(5, "No more links available for returning instance. Call 911.");        }
    }


private:
    struct MMLink {
        MMLink *next_{nullptr};
        T *object_;
    };

    bool initialized_{false};
    std::mutex listMutex_;
    MMLink *headAvailable_{nullptr};
    MMLink *headAvailableLink_{nullptr};
    uint32_t usedObjects_{0};
    uint32_t totObjects_{0};
    uint32_t increment_{0};
    uint32_t maxIncrement_{0};
    uint32_t totIncrements_{0};
    MMLink *incrementsLinkArray_[MAX_OBJETS_INCREMENTS + 1];
    T *incrementsObjectArray_[MAX_OBJETS_INCREMENTS + 1];

    void initialize(uint32_t numInstances) {
        bool res = allocateMemForInstances(numInstances, 0);

        if (res) {
            headAvailable_ = incrementsLinkArray_[0];
            initialized_ = true;
        } else {
            std::cerr << "Error initializing MemoryManager for type " << typeid(T).name() << std::endl;
        }
    }

    void initialize(uint32_t numInstances, uint32_t increment, uint32_t maxIncrement) {
        initialize(numInstances);
        increment_ = increment;
        if (maxIncrement > MAX_OBJETS_INCREMENTS) {
            std::cerr << "Warning initializing MemoryManager for type " << typeid(T).name()
                    << ": Max number of increments is " << MAX_OBJETS_INCREMENTS
                    << "but received: " << maxIncrement << std::endl;
            maxIncrement_ = MAX_OBJETS_INCREMENTS;
        } else {
            maxIncrement_ = maxIncrement;
        }
    }

    bool allocateMemForInstances(uint32_t numInstances, uint16_t index) {
        incrementsLinkArray_[index] = (MMLink *)std::malloc(numInstances * sizeof(MMLink));
        T *instances = (T *)std::malloc(numInstances * sizeof(T));
        incrementsObjectArray_[index] = instances;

        if (incrementsLinkArray_[index] == nullptr || instances == nullptr) {
            std::cerr << "Error allocating more memory in MemoryManager for type " << typeid(T).name() << " instances: " << numInstances << std::endl;
            return false;
        } else {
            uint32_t i;
            for(i = 0; i < (numInstances - 1); i++) {
                incrementsLinkArray_[index][i].next_ = &incrementsLinkArray_[index][i + 1];
                incrementsLinkArray_[index][i].object_ = &instances[i];
            }
            //Last element (numIsntances - 1)
            incrementsLinkArray_[index][i].next_ = nullptr;
            incrementsLinkArray_[index][i].object_ = &instances[i];
            totObjects_ += numInstances;

            return true;
        }
    }

    T *useFirstAvailableObject() {
        MMLink *instLink = headAvailable_;
        headAvailable_ = headAvailable_->next_;
        instLink->next_ = headAvailableLink_;
        headAvailableLink_ = instLink;
        usedObjects_++;

        return instLink->object_;
    }

    void destroyEverything() {
        if (usedObjects_ > 0) {
            std::cerr << "There are " << usedObjects_ << " usedObjects still. This means there is a memory leak in " << typeid(T).name() << std::endl;
        }
        if (headAvailableLink_) {
            std::cerr << "There are available links. This means there is a memory leak in " << typeid(T).name() << std::endl;
        }
        for(uint32_t i = 0; i <= totIncrements_; i++) {
            free(incrementsLinkArray_[i]);
            free(incrementsObjectArray_[i]);
        }
    }

};

} // namespace objmem_manager

#endif /* MEMORYMANAGER_H_ */
