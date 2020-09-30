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
