## Команды для проверки

**Посмотреть все VRF в системе**
```bash
ip vrf show
```

**Посмотреть детально все VXLAN и их VNI (маркеры)**
```bash
ip -d link show type vxlan
```

**Посмотреть вообще все сетевые интерфейсы в виде компактного списка**
```bash
ip brief link show
```

## Команды для удаления

**Для Клиента А (VNI 100)**
```bash
sudo ip link del vrf-client-a
sudo ip link del vxlan100
```

**Для Клиента Б (VNI 200)**
```bash
sudo ip link del vrf-client-b
sudo ip link del vxlan200
```

## NFT таблицы

```bash
sudo nft list tables
```

## Как nftables общается с ядром

`nftables` живет в ядре Linux. Пользовательские программы не редактируют файл и не обязаны запускать `nft` CLI. Они общаются с ядром через netlink socket:

```text
приложение
  -> NETLINK_NETFILTER socket
  -> nfnetlink
  -> nf_tables
  -> правила firewall в ядре
```

Go-библиотека `github.com/google/nftables` делает то же самое: собирает Go-структуры в netlink-сообщения и отправляет их в ядро. `nft` CLI тоже в итоге отправляет netlink-сообщения, просто делает это как отдельная утилита.

Для проверки существования правила нужно запросить правила из chain, разобрать выражения и сравнить их с тем, что приложение хочет создать. Отдельной команды "найти правило по содержимому" в `nft` нет.

Основные nftables-команды netlink для правил:

```text
NFT_MSG_GETRULE  - получить правила
NFT_MSG_NEWRULE  - добавить правило
NFT_MSG_DELRULE  - удалить правило
```

Основные атрибуты rule:

```text
NFTA_RULE_TABLE        - имя таблицы
NFTA_RULE_CHAIN        - имя chain
NFTA_RULE_HANDLE       - handle правила
NFTA_RULE_EXPRESSIONS  - список выражений правила
NFTA_RULE_USERDATA     - пользовательские данные правила
```

Примерно это соответствует CLI-командам:

```bash
# Получить правила chain вместе с handle
sudo nft -a list chain inet vrd-100-filter filterchain

# Добавить правило
sudo nft add rule inet vrd-100-filter filterchain tcp dport 443 accept

# Удалить правило по handle
sudo nft delete rule inet vrd-100-filter filterchain handle 12
```

## Полезные исходники и документация

Сторона ядра, которая принимает nftables netlink-команды:

- https://github.com/torvalds/linux/blob/master/net/netfilter/nf_tables_api.c
- https://github.com/torvalds/linux/blob/master/net/netfilter/nfnetlink.c

UAPI-константы команд, атрибутов и выражений:

- https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter/nf_tables.h
- https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter/nfnetlink.h
- https://github.com/torvalds/linux/blob/master/include/uapi/linux/netlink.h

Документация по netlink socket:

- https://man7.org/linux/man-pages/man7/netlink.7.html
- https://man7.org/linux/man-pages/man3/netlink.3.html
- https://docs.kernel.org/userspace-api/netlink/index.html
- https://docs.kernel.org/networking/netlink_spec/nftables.html

Пользовательские исходники:

- `nft` CLI: https://git.netfilter.org/nftables/
- netlink-часть `nft` CLI: https://git.netfilter.org/nftables/tree/src/netlink.c
- libmnl/socket helper: https://git.netfilter.org/nftables/tree/src/mnl.c
- libnftnl: https://git.netfilter.org/libnftnl/
- libnftnl rule encoding: https://git.netfilter.org/libnftnl/tree/src/rule.c
- libnftnl expr encoding: https://git.netfilter.org/libnftnl/tree/src/expr.c
