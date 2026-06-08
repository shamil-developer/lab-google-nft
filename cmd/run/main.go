package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/shamil-developer/lab-google-nft/internal/application"
	trafficfilter "github.com/shamil-developer/lab-google-nft/internal/infrastructure/traffic_filter"
)

// Функция зачистки, которую мы засунем в defer
func cleanup() {
	slog.Info("--- Начинаем зачистку системы (классический cleanup) ---")

	// Удаляем nftables таблицы (они сами удалят все правила внутри)
	_ = exec.Command("nft", "delete", "table", "inet", "vrd-100-filter").Run()
	_ = exec.Command("nft", "delete", "table", "inet", "vrd-200-filter").Run()

	// Удаляем интерфейсы Клиента А
	_ = exec.Command("ip", "link", "del", "vrf-client-a").Run()
	_ = exec.Command("ip", "link", "del", "vxlan100").Run()

	// Удаляем интерфейсы Клиента Б
	_ = exec.Command("ip", "link", "del", "vrf-client-b").Run()
	_ = exec.Command("ip", "link", "del", "vxlan200").Run()

	slog.Info("Все тестовые VRF, VXLAN и nftables таблицы успешно удалены. Система чиста!")
}

func main() {
	slog.Info("Работа началась...")

	// ГАРАНТИЯ ЗАЧИСТКИ: defer сработает при выходе из main (даже при панике)
	defer cleanup()

	// Настраиваем перехват Ctrl+C (SIGINT) и закрытия терминала (SIGTERM)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Канал для отслеживания шагов пользователя
	userSteps := make(chan struct{})

	slog.Info("--- Создаем сетевую структуру (VRF и VXLAN) ---")

	// ================= КЛИЕНТ А (VNI 100) =================
	_ = exec.Command("ip", "link", "add", "vrf-client-a", "type", "vrf", "table", "10").Run()
	_ = exec.Command("ip", "link", "set", "vrf-client-a", "up").Run()
	_ = exec.Command("ip", "link", "add", "vxlan100", "type", "vxlan", "id", "100", "dstport", "4789", "dev", "lo").Run()
	_ = exec.Command("ip", "link", "set", "vxlan100", "master", "vrf-client-a").Run()
	_ = exec.Command("ip", "link", "set", "vxlan100", "up").Run()

	// ================= КЛИЕНТ Б (VNI 200) =================
	_ = exec.Command("ip", "link", "add", "vrf-client-b", "type", "vrf", "table", "20").Run()
	_ = exec.Command("ip", "link", "set", "vrf-client-b", "up").Run()
	_ = exec.Command("ip", "link", "add", "vxlan200", "type", "vxlan", "id", "200", "dstport", "4789", "dev", "lo").Run()
	_ = exec.Command("ip", "link", "set", "vxlan200", "master", "vrf-client-b").Run()
	_ = exec.Command("ip", "link", "set", "vxlan200", "up").Run()

	// ================= NFTABLES: создаём таблицы и цепочки для VRF =================
	_ = exec.Command("nft", "add", "table", "inet", "vrd-100-filter").Run()
	_ = exec.Command("nft", "add", "chain", "inet", "vrd-100-filter", "filterchain",
		"{", "type", "filter", "hook", "forward", "priority", "0", ";", "}").Run()
	_ = exec.Command("nft", "add", "table", "inet", "vrd-200-filter").Run()
	_ = exec.Command("nft", "add", "chain", "inet", "vrd-200-filter", "filterchain",
		"{", "type", "filter", "hook", "forward", "priority", "0", ";", "}").Run()

	slog.Info("Интерфейсы созданы, nftables таблицы заведены!")

	// ----------------------------------------------------
	// ШАГ 1: Ждем ENTER в отдельной горутине
	// ----------------------------------------------------
	go func() {
		fmt.Println("\n[ПАУЗА 1] Нажми ENTER, чтобы вывести списки VRF и VXLAN...")
		_, _ = fmt.Scanln()
		userSteps <- struct{}{}
	}()

	// Ждем либо нажатия ENTER, либо Ctrl+C
	select {
	case <-userSteps:
		// Пользователь нажал Enter, идем дальше
	case sig := <-sigs:
		slog.Warn("Программа прервана пользователем!", "сигнал", sig)
		return // Выходим, defer сам всё удалит
	}

	// ================= ПРОВЕРКА РЕЗУЛЬТАТА =================
	slog.Info("--- Список VRF ---")
	cmdVrf := exec.Command("ip", "vrf", "show")
	cmdVrf.Stdout = os.Stdout
	cmdVrf.Stderr = os.Stderr
	_ = cmdVrf.Run()

	slog.Info("--- Список VXLAN и их VNI ---")
	cmdVxlan := exec.Command("ip", "-d", "link", "show", "type", "vxlan")
	cmdVxlan.Stdout = os.Stdout
	cmdVxlan.Stderr = os.Stderr
	_ = cmdVxlan.Run()

	// ----------------------------------------------------
	// ШАГ 2: Ждем ENTER перед выходом
	// ----------------------------------------------------
	go func() {
		fmt.Println("\n[ПАУЗА 2] Нажми ENTER, чтобы применить правила фильтрации через nftables...")
		_, _ = fmt.Scanln()
		userSteps <- struct{}{}
	}()

	// Снова ждем либо ENTER, либо Ctrl+C
	select {
	case <-userSteps:
		slog.Info("Пользователь завершил работу по кнопке.")
	case sig := <-sigs:
		slog.Warn("Программа прервана пользователем на втором шаге!", "сигнал", sig)
	}

	// ----------------------------------------------------
	// ШАГ 3: Применяем правила фильтрации через nftables
	// ----------------------------------------------------

	slog.Info("--- Начинаем настройку nftables ---")

	ctx := context.Background()

	cfg := trafficfilter.Config{
		NetlinkSocket: "/run/nftables.sock", // стандартный путь сокета nftables в Linux
	}
	filterProvider := trafficfilter.NewProviderWithConfig(cfg)

	type testRule struct {
		vni  uint32
		rule application.Rule
	}

	rules := []testRule{
		// VRF А (VNI 100):
		// TCP dst port 443, accept
		{vni: 100, rule: application.Rule{Protocol: application.ProtocolTCP, DestinationPort: ptr(uint32(443)), Action: application.ActionAllow}},
		// TCP dst port 80, accept
		{vni: 100, rule: application.Rule{Protocol: application.ProtocolTCP, DestinationPort: ptr(uint32(80)), Action: application.ActionAllow}},
		// UDP src port 53, accept
		{vni: 100, rule: application.Rule{Protocol: application.ProtocolUDP, SourcePort: ptr(uint32(53)), Action: application.ActionAllow}},
		// ICMP, drop
		{vni: 100, rule: application.Rule{Protocol: application.ProtocolICMP, Action: application.ActionDrop}},
		// TCP src 10.0.0.0/24, accept
		{vni: 100, rule: application.Rule{Protocol: application.ProtocolTCP, SourcePrefix: "10.0.0.0/24", Action: application.ActionAllow}},
		// UDP dst 192.168.1.0/24, drop
		{vni: 100, rule: application.Rule{Protocol: application.ProtocolUDP, DestinationPrefix: "192.168.1.0/24", Action: application.ActionDrop}},
		// TCP src port 8080 + dst 10.10.0.0/16, accept
		{vni: 100, rule: application.Rule{Protocol: application.ProtocolTCP, SourcePort: ptr(uint32(8080)), DestinationPrefix: "10.10.0.0/16", Action: application.ActionAllow}},
		// TCP dst port 22, accept
		{vni: 100, rule: application.Rule{Protocol: application.ProtocolTCP, DestinationPort: ptr(uint32(22)), Action: application.ActionAllow}},

		// VRF Б (VNI 200):
		// TCP dst port 443, accept
		{vni: 200, rule: application.Rule{Protocol: application.ProtocolTCP, DestinationPort: ptr(uint32(443)), Action: application.ActionAllow}},
		// UDP dst port 1194, accept
		{vni: 200, rule: application.Rule{Protocol: application.ProtocolUDP, DestinationPort: ptr(uint32(1194)), Action: application.ActionAllow}},
		// TCP src 172.16.0.0/12, drop
		{vni: 200, rule: application.Rule{Protocol: application.ProtocolTCP, SourcePrefix: "172.16.0.0/12", Action: application.ActionDrop}},
	}

	slog.Info("--- Начинаем создание набора правил ---")

	for i, tr := range rules {
		err := filterProvider.ApplyRule(ctx, application.ApplyRuleRequest{VNI: tr.vni, Rule: tr.rule})
		if err != nil {
			slog.Error("ApplyRule failed", "num", i+1, "vni", tr.vni, "error", err)
		} else {
			slog.Info("Правило создано", "num", i+1, "vni", tr.vni)
		}
	}

	// ----------------------------------------------------
	// ШАГ 4: Ждем ENTER перед проверкой дубликата
	// ----------------------------------------------------
	go func() {
		fmt.Println("\n[ПАУЗА 3] Нажми ENTER, чтобы проверить защиту от дубликатов...")
		_, _ = fmt.Scanln()
		userSteps <- struct{}{}
	}()

	select {
	case <-userSteps:
	case sig := <-sigs:
		slog.Warn("Программа прервана пользователем!", "сигнал", sig)
		return
	}

	// Пробуем добавить такое же правило повторно — должны поймать ошибку "rule already exists"
	err := filterProvider.ApplyRule(ctx, application.ApplyRuleRequest{
		VNI: 100,
		Rule: application.Rule{
			Protocol:        application.ProtocolTCP,
			DestinationPort: ptr(uint32(443)),
			Action:          application.ActionAllow,
		},
	})
	if err != nil {
		slog.Error("ApplyRule дубликат failed (ожидаемо)", "error", err)
	} else {
		slog.Info("ApplyRule дубликат создан (неожиданно)")
	}

	// ----------------------------------------------------
	// ШАГ 5: Ждем ENTER перед удалением правила
	// ----------------------------------------------------
	go func() {
		fmt.Println("\n[ПАУЗА 4] Нажми ENTER, чтобы удалить правило (TCP dst 443 VNI 100)...")
		_, _ = fmt.Scanln()
		userSteps <- struct{}{}
	}()

	select {
	case <-userSteps:
	case sig := <-sigs:
		slog.Warn("Программа прервана пользователем!", "сигнал", sig)
		return
	}

	duplicateRule := application.DeleteRuleRequest{
		VNI: 100,
		Rule: application.Rule{
			Protocol:        application.ProtocolTCP,
			DestinationPort: ptr(uint32(443)),
			Action:          application.ActionAllow,
		},
	}

	// Удаляем правило первый раз — должно успешно удалиться
	slog.Info("--- Удаляем правило #1 ---")
	if err := filterProvider.DeleteRule(ctx, duplicateRule); err != nil {
		slog.Error("DeleteRule #1 failed", "error", err)
	} else {
		slog.Info("DeleteRule #1 успешно")
	}

	// ----------------------------------------------------
	// ШАГ 6: Ждем ENTER перед повторным удалением
	// ----------------------------------------------------
	go func() {
		fmt.Println("\n[ПАУЗА 5] Нажми ENTER, чтобы попробовать удалить то же правило повторно...")
		_, _ = fmt.Scanln()
		userSteps <- struct{}{}
	}()

	select {
	case <-userSteps:
	case sig := <-sigs:
		slog.Warn("Программа прервана пользователем!", "сигнал", sig)
		return
	}

	// Удаляем правило второй раз — правило уже удалено, должен быть лог а не ошибка
	slog.Info("--- Удаляем правило #2 (повторно) ---")
	if err := filterProvider.DeleteRule(ctx, duplicateRule); err != nil {
		slog.Error("DeleteRule #2 failed", "error", err)
	} else {
		slog.Info("DeleteRule #2 успешно (правило уже было удалено)")
	}

	// ----------------------------------------------------
	// ШАГ 7: Ждем ENTER перед чисткой VRF 100
	// ----------------------------------------------------
	go func() {
		fmt.Println("\n[ПАУЗА 6] Нажми ENTER, чтобы очистить все правила для VNI 100...")
		_, _ = fmt.Scanln()
		userSteps <- struct{}{}
	}()

	select {
	case <-userSteps:
	case sig := <-sigs:
		slog.Warn("Программа прервана пользователем!", "сигнал", sig)
		return
	}

	slog.Info("--- Чистим все firewall-правила для VNI 100 ---")
	if err := filterProvider.CleanupVRFRules(ctx, application.CleanupVRFRulesRequest{VNI: 100}); err != nil {
		slog.Error("CleanupVRFRules failed", "error", err)
	} else {
		slog.Info("CleanupVRFRules для VNI 100 завершён успешно")
	}

	// ----------------------------------------------------
	// ШАГ 8: Ждем ENTER перед завершением
	// ----------------------------------------------------
	go func() {
		fmt.Println("\n[ПАУЗА 7] Нажми ENTER, чтобы завершить программу и удалить интерфейсы...")
		_, _ = fmt.Scanln()
		userSteps <- struct{}{}
	}()

	select {
	case <-userSteps:
		slog.Info("Завершаем работу, сейчас отработает cleanup...")
	case sig := <-sigs:
		slog.Warn("Программа прервана пользователем!", "сигнал", sig)
	}

	// Конец main. Сейчас автоматически вызовется функция cleanup() из defer
}

func ptr[T any](v T) *T {
	return &v
}
