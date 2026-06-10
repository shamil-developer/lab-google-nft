# Traffic Filter Provider

Провайдер управляет firewall-правилами nftables для VRF/VNI.

Каждый VNI соответствует отдельной nftables table:

```text
vrd-<VNI>-filter
```

Внутри table используется chain:

```text
filterchain
```

Провайдер работает только с `inet` family.

## Rule

`Rule` описывает одно firewall-правило.

Поля:

- `Protocol` - обязательный протокол правила.
- `SourcePrefix` - source IP prefix в CIDR-формате.
- `DestinationPrefix` - destination IP prefix в CIDR-формате.
- `SourcePort` - source port.
- `DestinationPort` - destination port.
- `Action` - действие правила: allow или drop.

Правило может содержать несколько условий одновременно. Например:

```text
tcp source prefix 10.0.0.0/24 destination port 443 allow
```

Такое правило сработает только если совпали все условия.

## Общие правила валидации

Эти правила применяются к `ApplyRule` и `DeleteRule`.

- `VNI` должен быть задан и не может быть `0`.
- `Protocol` должен быть задан.
- Поддерживаемые protocol: `TCP`, `UDP`, `ICMP`.
- `Action` должен быть задан.
- Поддерживаемые action: `Allow`, `Drop`.
- `SourcePrefix`, если задан, должен быть валидным CIDR.
- `DestinationPrefix`, если задан, должен быть валидным CIDR.
- `SourcePort` и `DestinationPort` можно использовать только с `TCP` или `UDP`.
- Port должен быть в диапазоне `0..65535`.

Примеры валидных CIDR:

```text
10.0.0.0/24
10.0.0.1/32
2001:db8::/64
2001:db8::1/128
```

Protocol-only правило валидно:

```text
icmp drop
```

Это означает: удалить или применить правило для всего ICMP-трафика.

## ApplyRule

`ApplyRule` добавляет новое firewall-правило в table конкретного VNI.

Принимает:

- `VNI`
- `Rule`

Что делает:

1. Проверяет request.
2. Находит nftables table `vrd-<VNI>-filter`.
3. Находит chain `filterchain`.
4. Получает существующие правила chain.
5. Собирает nftables expressions из `Rule`.
6. Сравнивает новое правило с существующими.
7. Если такое правило уже есть, возвращает ошибку.
8. Если правила нет, добавляет его.
9. Выполняет `Flush`.

Бизнес-смысл:

- Нельзя создать дубликат одного и того же правила.
- Добавление считается успешным только после успешного `Flush`.
- Если request невалидный, provider не обращается к nftables.

## DeleteRule

`DeleteRule` удаляет firewall-правило из table конкретного VNI.

Принимает:

- `VNI`
- `Rule`

Что делает:

1. Проверяет request.
2. Находит nftables table `vrd-<VNI>-filter`.
3. Находит chain `filterchain`.
4. Получает существующие правила chain.
5. Собирает nftables expressions из `Rule`.
6. Сравнивает собранное правило с существующими.
7. Если правило найдено, удаляет его.
8. Выполняет `Flush`.
9. Если правило не найдено, ничего не делает и не возвращает ошибку.

Бизнес-смысл:

- Удаление идемпотентное.
- Повторное удаление уже удаленного правила не считается ошибкой.
- Удаляется только правило, expressions которого совпали с запрошенным `Rule`.
- Если request невалидный, provider не обращается к nftables.

## CleanupVRFRules

`CleanupVRFRules` очищает firewall-правила для конкретного VNI.

Принимает:

- `VNI`

Что делает:

1. Проверяет request.
2. Находит nftables table `vrd-<VNI>-filter`.
3. Находит chain `filterchain`.
4. Получает существующие правила chain.
5. Удаляет правила, у которых есть expressions.
6. Пропускает правила без expressions.
7. Выполняет `Flush`.

Бизнес-смысл:

- Метод предназначен для очистки правил внутри VRF/table, которая принадлежит этому provider.
- Правила с expressions считаются firewall-правилами и удаляются.
- Пустые правила пропускаются.
- Если request невалидный, provider не обращается к nftables.

## Сравнение правил

Для проверки дубликатов и поиска правила на удаление provider сравнивает nftables expressions.

Сравнение идет так:

1. Проверяется длина списка expressions.
2. Каждое expression маршалится в netlink bytes.
3. Полученные bytes сравниваются.

Порядок expressions учитывается.

Это важно, потому что nftables правило является последовательностью expressions, и provider должен сравнивать именно то, что будет отправлено в nftables.

## Что покрывают unit-тесты

Unit-тесты проверяют:

- сборку expressions из `Rule`;
- сравнение expressions;
- валидацию правил;
- добавление правила;
- защиту от дублей;
- удаление найденного правила;
- идемпотентное удаление отсутствующего правила;
- cleanup правил VRF;
- ошибки nftables-адаптера;
- что невалидные requests не доходят до nftables connection.

Тесты provider используют generated gomock для `nftConn`.

Mock генерируется командой:

```bash
make mock
```
