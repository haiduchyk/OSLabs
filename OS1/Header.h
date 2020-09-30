#pragma once
struct Header
{
    bool isFree;
    uint64_t currentSize;
    uint64_t prevSize;
};