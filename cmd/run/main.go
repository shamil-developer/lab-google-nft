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

	// Удаляем интерфейсы Клиента А
	_ = exec.Command("ip", "link", "del", "vrf-client-a").Run()
	_ = exec.Command("ip", "link", "del", "vxlan100").Run()

	// Удаляем интерфейсы Клиента Б
	_ = exec.Command("ip", "link", "del", "vrf-client-b").Run()
	_ = exec.Command("ip", "link", "del", "vxlan200").Run()

	slog.Info("Все тестовые VRF и VXLAN успешно удалены. Система чиста!")
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

	slog.Info("Интерфейсы созданы!")

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
		fmt.Println("\n[ПАУЗА 2] Нажми ENTER, чтобы завершить программу и удалить интерфейсы...")
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
	// ШАГ 3: Началась основная логика работы кода на го
	// ----------------------------------------------------

	var _ context.Context = context.Background() // ctx для будущего использования

	cfg := trafficfilter.Config{
		NetlinkSocket: "/run/nftables.sock", // стандартный путь сокета nftables в Linux
	}
	var filterProvider application.TrafficFilterProvider = trafficfilter.NewProviderWithConfig(cfg)

	_ = filterProvider

	// Пример использования:
	// filterProvider.ApplyRule(ctx, application.ApplyRuleRequest{
	// 	VNI: 100,
	// 	Rule: application.Rule{
	// 		Protocol:     application.ProtocolTCP,
	// 		SourcePrefix: "10.0.0.0/24",
	// 		Action:       application.ActionAllow,
	// 	},
	// })

	// filterProvider.DeleteRule(ctx, application.DeleteRuleRequest{})
	// filterProvider.CleanupVRFRules(ctx, application.CleanupVRFRulesRequest{VNI: 100})

	// Конец main. Сейчас автоматически вызовется функция cleanup() из defer
}
