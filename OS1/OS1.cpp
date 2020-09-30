#include <iostream>
#include <string>
#include "Header.h"
#include "Allocator.h"
#include "MemTest.h";

const int SIZE = 1000;
const int ALIGN = 8;
const int HEADER_SIZE = 8;

Allocator allocator;

bool isBlockFree(uint64_t header)
{
    if (header & ((uint64_t)1 << 63)) return true;
    return false;
}

uint32_t getCurrentSize(uint64_t header)
{
    uint64_t mask = 0xFFFFFFFE;
    uint32_t res = (mask & header) >> 1;
    return res;
}

uint32_t getPrevSize(uint64_t header)
{
    uint64_t mask = 0x7FFFFFFF00000000;
    uint32_t res = (mask & header) >> 33;
    return res;
}

uint64_t encryptHeader(Header header)
{
    uint64_t result = 0;
    if (header.isFree) result |= ((uint64_t)1 << 63);
    uint64_t maskCur = 0xFFFFFFFE;
    uint64_t maskNext = 0xFFFFFFFE00000000;

    result |= (maskCur & (header.currentSize << 1));
    result |= (maskNext & (header.prevSize << 33));
    return result;
}

void* mem_alloc(size_t size)
{
    int align = size % ALIGN;
    if (align != 0) size = ALIGN - align + size;
    char* blockPtr = allocator.start; 
    uint32_t currentSize = getCurrentSize(*(uint64_t*)blockPtr); 
    
    bool outOfMem = false;

    while (!isBlockFree(*(uint64_t*)blockPtr) || currentSize < size)
    {
        blockPtr += currentSize + HEADER_SIZE;
        if (blockPtr >= (allocator.start + allocator.totalSize)) 
        {
            outOfMem = true;
            break;
        }
        uint64_t header = *(uint64_t*)blockPtr;
        currentSize = getCurrentSize(*(uint64_t*)blockPtr);
    }
    if (outOfMem) return NULL;

    Header currentHeader = {false, size, getPrevSize(*(uint64_t*)blockPtr) };

    int32_t nextSize = currentSize - size - HEADER_SIZE;
    if (nextSize >= 0)
    {
        Header nextHeader = {true, nextSize, size};
        char* nextPtr = blockPtr + size + HEADER_SIZE;

        *(uint64_t*)nextPtr = encryptHeader(nextHeader);

        char* nextNextPtr = nextPtr + nextSize + HEADER_SIZE; 
        if (nextNextPtr < allocator.start + allocator.totalSize)
        {
            Header nextNextHeader = { false, getCurrentSize(*(uint64_t*)nextNextPtr), nextSize };
            *(uint64_t*)nextNextPtr = encryptHeader(nextNextHeader);
        }
    }

    *(uint64_t*)blockPtr = encryptHeader(currentHeader);

    void* result = blockPtr + HEADER_SIZE;
    return result;
}

void mem_free(void* addr)
{
    addr = (char*)addr - HEADER_SIZE;
    uint64_t header = *(uint64_t*)addr;

    uint32_t curSize = getCurrentSize(header);
    char* nextPtr = (char*)addr + curSize + HEADER_SIZE;
    if (nextPtr >= (allocator.start + allocator.totalSize)) nextPtr = NULL;

    uint32_t prevSize = getPrevSize(header);
    char* prevPtr = (char*)addr - prevSize - HEADER_SIZE;

    if (prevPtr < allocator.start) prevPtr = NULL;

    uint64_t prevHeader = NULL;
    if (prevPtr != NULL) prevHeader = *(uint64_t*)prevPtr;

    uint64_t nextHeader = NULL;
    if (nextPtr != NULL) nextHeader = *(uint64_t*)nextPtr;

    bool isPrevBlockExistsAndFree = prevHeader != NULL && isBlockFree(prevHeader);

    bool isNextBlockExistsAndFree = nextHeader != NULL && isBlockFree(nextHeader);

    char* newHeaderPtr;
    uint32_t newSize;
    uint32_t newPrevSize;

    bool isMerged = true;
    if (isPrevBlockExistsAndFree && isNextBlockExistsAndFree)
    {
        newHeaderPtr = prevPtr;
        newSize = prevSize + curSize + getCurrentSize(*(uint64_t*)nextPtr) + 16;
        newPrevSize = getPrevSize(*(uint64_t*)prevPtr);
    }
    else if (isPrevBlockExistsAndFree)
    {
        newHeaderPtr = prevPtr;
        newSize = prevSize + curSize + HEADER_SIZE;
        newPrevSize = getPrevSize(*(uint64_t*)prevPtr);
    }
    else if (isNextBlockExistsAndFree)
    {
        newHeaderPtr = (char*)addr;
        newSize = curSize + getCurrentSize(*(uint64_t*)nextPtr) + HEADER_SIZE;
        newPrevSize = prevSize;
    }
    else
    {
        newHeaderPtr = (char*)addr;
        newSize = curSize;
        newPrevSize = prevSize;

        isMerged = false;
    }

    Header newHeader = {true, newSize, newPrevSize};
    *(uint64_t*)newHeaderPtr = encryptHeader(newHeader);

    nextPtr = newHeaderPtr + newSize + HEADER_SIZE;
    if (isMerged && nextPtr < (allocator.start + allocator.totalSize))
    {
        Header newNextHeader = {false, getCurrentSize(*(uint64_t*)nextPtr), newSize};
        *(uint64_t*)nextPtr = encryptHeader(newNextHeader);
    }
}

void* mem_realloc(void* addr, size_t size) 
{
    if (addr == NULL) return mem_alloc(size);
    uint64_t* curPtr = (uint64_t*)((char*)addr - HEADER_SIZE);
    uint64_t header = *curPtr;
    uint32_t currentSize = getCurrentSize(header);
    uint32_t prevSize = getPrevSize(header);
    if (currentSize == size) return addr;

    mem_free(addr);
    void* newPtr = mem_alloc(size);
    if (newPtr == NULL)
    {
        Header currentHeader = { false, currentSize, prevSize };
        *curPtr = encryptHeader(currentHeader);
        uint64_t* prevPtr = (uint64_t*)((char*)addr - prevSize - HEADER_SIZE * 2);
        if ((char*)prevPtr >= allocator.start)
        {
            Header prevHeader = { isBlockFree(*prevPtr), prevSize, getPrevSize(*prevPtr) };
            *prevPtr = encryptHeader(prevHeader);
        }

        uint64_t* nextPtr = (uint64_t*)((char*)addr + currentSize);
        uint32_t nextSize;
        if ((char*)nextPtr < (allocator.start + allocator.totalSize))
        {
            nextSize = getCurrentSize(*nextPtr);
            Header nextHeader = { isBlockFree(*nextPtr), nextSize, currentSize };
            *nextPtr = encryptHeader(nextHeader);
        }

        uint64_t* nextNextPtr = (uint64_t*)((char*)nextPtr + nextSize + HEADER_SIZE);
        if ((char*)nextNextPtr < (allocator.start + allocator.totalSize))
        {
            Header nextNextHeader = { isBlockFree(*nextNextPtr), getCurrentSize(*nextNextPtr), nextSize };
            *nextNextPtr = encryptHeader(nextNextHeader);
        }
        return NULL;
    }

    if (newPtr == addr) return addr; // если выделенный указатель совпадает с предыдущим, возвращаем его

    if (size < currentSize) memcpy(newPtr, addr, size);
    else memcpy(newPtr, addr, currentSize);

    return newPtr;
}

void mem_dump()
{
    char* ptr = allocator.start;
    uint64_t header;
    uint32_t size;
    while (ptr < allocator.start + allocator.totalSize)
    {
        header = *(uint64_t*)ptr;
        size = getCurrentSize(header);
        bool isFree = isBlockFree(header);

        std::cout << "Pointer = " + std::to_string((uint64_t)ptr) + " | size = " + std::to_string(size) + " | ";
        std::cout << (isFree ? "free\n" : "busy\n");
        ptr += size + HEADER_SIZE;
    }
    std::cout << (std::string)"--------------------------------------" + "\n";
}

void allocator_init(int size, int headerSize)
{
    char* memory = (char*)malloc(size);
    allocator = {SIZE, memory};
    Header firstBlockHdr = { true, size - headerSize, 0 };

    uint64_t firstHeader = encryptHeader(firstBlockHdr);
    *(uint64_t*)allocator.start = firstHeader;
}


int main()
{
    allocator_init(SIZE, HEADER_SIZE);
    mem_test();
    mem_dump();
}
