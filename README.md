# Шифрование: клиент-сервер

В репозитории реализована простейшая клиент серверная архитектура на основе сокетов.

**Задача**: реализовать алгоритмы симметричного и асимметричного шифрования

### Симметричное шифрование
В качестве алгоритма выбран AES – Advanced Encryption Standard. 

Алгоритм AES (Advanced Encryption Standard) - это симметричный алгоритм блочного шифрования, 
который используется для защиты данных. Он основан на замене байтов и перемешивании данных в блоках размером 128 бит.
Алгоритм состоит из нескольких раундов, каждый из которых включает в себя несколько шагов: 
- замену байтов
- перемешивание байтов
- комбинирование байтов
- добавление ключа
 
Ключ используется для шифрования и дешифрования данных, и его длина может быть 128, 192 или 256 бит. 

Пример:

Перевод фразы в зашифрованный вид с помощью ключа происходит следующим образом:

1. Фраза "Сегодня я куплю мороженое" преобразуется в бинарный формат, то есть каждый символ заменяется на соответствующий ему код ASCII.

2. Полученный бинарный код разбивается на блоки по 128 бит (16 байт).

3. Для каждого блока применяется алгоритм шифрования AES-256 с использованием ключа "mysecretkey12345".

4. Зашифрованные блоки объединяются в одну строку, которая и будет результатом шифрования.

5. Полученная зашифрованная строка может быть передана по сети или сохранена в файле.

6. Для дешифровки строки необходимо применить обратный алгоритм: разбить строку на блоки по 128 бит, применить к каждому блоку алгоритм расшифровки AES-256 с использованием того же ключа "mysecretkey12345", объединить расшифрованные блоки в исходную фразу.

В питоне выбрана реализация AES – Fernet из модуля cryptography.

### Асимметричное шифрование
Алгоритм асимметричного шифрования RSA работает на основе использования двух ключей: открытого и закрытого. Открытый ключ может использоваться для шифрования данных, а закрытый ключ - для их расшифровки. 

Алгоритм состоит из следующих шагов:

1. Генерация ключей. Для начала генерируются два простых числа p и q, затем вычисляется их произведение n = p * q. Далее
выбирается число e, которое является взаимно простым с числом (p-1) * (q-1). Затем вычисляется число d, которое является обратным к числу e по модулю (p-1) * (q-1). Полученные числа e и n образуют открытый ключ, а d и n - закрытый ключ.

2. Шифрование данных. Для шифрования данных используется открытый ключ. Каждый символ сообщения заменяется на числовое значение по таблице ASCII, затем это значение возведено в степень e по модулю n.

3. Расшифровка данных. Для расшифровки данных используется закрытый ключ. Зашифрованные данные возведены в степень d по модулю n, после чего полученные числовые значения заменяются на символы по таблице ASCII.

Преимущество алгоритма RSA заключается в том, что открытый ключ может быть распространен широко, без риска компрометации 
безопасности данных.

В питоне выбрана реализация алгоритма в библиотеке RSA