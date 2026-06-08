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
