#include <iostream>
#include <ctime>
#include "Mem.h"

void mem_test()
{
    srand(time(0));
    void* arr[100];
    int counter = 0;
    for (int i = 0; i < 10000; i++)
    {
        int random = rand() % 2;
        if (random == 0)
        {
            int randSize = rand() % 96 + 1;
            void* ptr = mem_alloc(randSize);
            if (ptr == NULL)
            {
                int randFreeIndex = rand() % counter--;
                mem_free(arr[randFreeIndex]);
                if (randFreeIndex != counter) arr[randFreeIndex] = arr[counter];
            }
            else arr[counter++] = ptr;
        }
        else if (counter > 0)
        {
            int randFreeIndex = rand() % counter--;
            mem_free(arr[randFreeIndex]);
            if (randFreeIndex != counter) arr[randFreeIndex] = arr[counter];
        }
    }
}