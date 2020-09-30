# Lab1
1.	Опис роботи алгоритму

Алокатор створює зв’язний список блоків пам’яті. На початку кожного блоку розташований заголовок розміром 64 біти, у якому вказані розмір поточного блоку (31 біт), розмір попереднього блоку (31 біт) та статус зайнятості поточного блоку (1 біт). Ще 1 біт залишається вільним. Така структура дозволяє знайти наступний та попередній блок пам’яті шляхом додавання або віднімання від вказівника на поточний блок розміру поточного або попереднього блоку.
Сам алокатор містить у собі два поля: вказівник на початок області пам’яті та розмір цієї області. Це дозволяє визначити межі адрес, в яких знаходиться ця область.

1.1 Алокація блоку

Перед алокацією запитуваний користувачем запит вирівнюється до 8 байт. Алокатор проходить по зв’язному списку існуючих блоків пам’яті, починаючи з першого. Кожний блок перевіряється на дві умови: чи він вільний та чи достатній в ньому обсяг пам’яті. Якщо обидві умови виконуються, то створюється новий заголовок для блоку пам’яті та записується у його початок. Якщо знайдений блок більший за запитаний користувачем, то для залишку цього блока також створюється заголовок та записується у його початок. Таким чином, фактично, блок більшого розміру поділяється на два блоки, один з яких віддається користувачу, а інший залишається вільним. При цьому змінюється заголовок наступного блоку пам’яті, оскільки необхідно змінити у ньому розмір попереднього блоку пам’яті, який став меншим внаслідок поділу.
Якщо при проходженні по зв’язному списку вказівник на наступний блок виходить за межі алокованої пам’яті (тобто адреса вказівника більша за суму адреси початку алокатора та його розміру), то блок пам’яті не виділяється і користувачу повертається нульовий вказівник (NULL).

1.2.Звільнення блоку

При звільненні блоку аналізуються 4 випадки: 
	1.Обидва сусідні блоки вільні;
	2.Лише попередній блок вільний;
	3.Лише наступний блок вільний;
	4.Кожний сусідній блок не є вільним.
В залежності від стану сусідніх блоків, вони об’єднуються з поточним у єдиний блок. Для цього змінюються їх заголовки відповідно до нових розмірів блоків, а також заголовок наступного за наступним блоком, щоб змінити значення розміру попереднього блоку, який був збільшений внаслідок об’єднання.

1.3.Реалокація блоку

При реалокації блоку алокатор спочатку помічає поточний блок як вільний та об’єднує його з сусідніми, якщо вони вільні також. Варто зазначити, що при цьому у блоці не змінюються дані: змінюється лише структура алокатора. Це дозволить в подальшому повернути вказівник на цей блок без копіювання даних, якщо не вдасться знайти блок більшого розміру. Далі здійснюється проходження по зв’язному списку блоків для пошуку блоку запитаного користувачем розміру. Фактично у реалізації викликається mem_alloc з новим розміром блоку. Якщо блок був успішно знайдений, то його вказівник порівнюється зі старим, і у разі співпадіння він повертається одразу (без копіювання даних). В іншому випадку дані копіюються зі старого блоку у новий. 
Якщо знайти новий блок не вдалося, то відновлюється попередня структура зв’язного списку блоків (заголовки поточного та сусіднього блоків редагуються на попередні) і повертається нульовий вказівник. Оскільки дані у старому блоці не були заторкнуті, то додатково щось робити більше не потрібно.

2.Оцінки часу

2.1.Оцінка часу пошуку вільного блоку

Пошук вільного блоку відбувається в середньому за час O(N/2) (N – кількість алокованих блоків пам’яті), тобто за лінійну кількість часу. У найліпшому випадку, коли вільний блок знаходиться у самому початку зв’язаного списку, складність складає О(1), тобто є константною. У найгіршому випадку, коли вільний блок знаходиться у самому кінці, часова складність складає О(N), оскільки потрібно пройтися по всім блокам у зв’язному списку. Це дає змогу стверджувати, що середній час для виділення нового блоку пам’яті не перевищує О(N), а отже, є лінійним. 

2.2. Оцінка часу звільнення блоку 

При звільненні блоку виконується лише перезапис заголовків цього та сусідніх блоків, а отже, часова складність є константною – О(N). 
3. Оцінка витрат пам’яті для зберігання службової інформації
На кожний блок пам’яті виділяється додатково 64 біти на заголовок, у якому 62 біти відводиться на значення розмірів поточного та попереднього блоків (по 31 біт) та 1 біт на статус зайнятості блоку. Ще 1 біт залишається не використаним. Відповідно до цього, чим менші розміри блоків, чим їх більше та чим більша фрагментація пам’яті, тим більшу питому вагу займають заголовки блоків. 

4. Опис переваг та недоліків розробленого алокатору

До переваг можна віднести миттєве звільнення пам'яті, швидке зменшення фрагментації завдяки склеюванню блоків при їх звільненні. Також фрагментація частково зменшується завдяки тому, що блоки алокуються у пам’яті по черзі, а не у випадковій області пам’яті. Таким чином часто у кінці залишається великий вільний блок (перевірено тестуванням).
До недоліків можна віднести відсутність спеціалізованого механізму дефрагментації пам’яті, через що після великої кількості операцій алокації та звільнення блоків пам’ять може бути значно фрагментована. Недоліком є лінійна часова складність алгоритму пошуку нового блоку. При великій кількості блоків це може спричинити суттєву затримку при алокації нового блоку. Також цей недолік стосується і реалокації блока.

Результат

![alt text](https://github.com/haiduchyk/OSLabs/blob/master/OS1/Result.png)

Основные функции
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
