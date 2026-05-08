package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/Vokkla/sni_tester/config"
	"github.com/Vokkla/sni_tester/output"
	"github.com/Vokkla/sni_tester/sni"
	"github.com/Vokkla/sni_tester/tester"
)

var cfg = config.DefaultConfig()

func main() {
	rootCmd := buildRootCommand()
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// buildRootCommand — строит корневую команду CLI
func buildRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "sni-tester",
		Short: "SNI Tester — проверка SNI для VLESS+Reality",
		Long: `SNI Tester — инструмент для проверки работоспособности SNI
с вашего текущего интернет-соединения (мобильный оператор, провайдер).

Примеры использования:
  sni-tester test --ip 1.1.1.1 --mode fast
  sni-tester test --ip 1.1.1.1 --mode full --fp firefox --workers 20
  sni-tester test --ip 1.1.1.1 --port 8443 --sni-file my-snis.txt --export singbox
  sni-tester update
  sni-tester scan --subnet 1.1.1.0/24`,
		Version: config.AppVersion,
	}

	// --- Команда test ---
	testCmd := &cobra.Command{
		Use:   "test",
		Short: "Запустить тестирование SNI",
		RunE:  runTest,
	}

	f := testCmd.Flags()
	f.StringVarP(&cfg.TargetIP, "ip", "i", "", "IP-адрес сервера для подключения (обязательно)")
	f.IntVarP(&cfg.Port, "port", "p", 443, "Порт TLS")
	f.StringVarP(&cfg.SNIFile, "sni-file", "f", "sni-candidates.txt", "Файл со списком SNI")
	f.StringVar(&cfg.Fingerprint, "fp", "chrome", "uTLS fingerprint: chrome, firefox, ios, android, safari, randomized")
	f.DurationVar(&cfg.HandshakeTimeout, "timeout", 5*time.Second, "Таймаут handshake")
	f.StringVarP(&cfg.Mode, "mode", "m", "fast", "Режим: fast (только handshake) | full (handshake+стабильность)")
	f.IntVarP(&cfg.Workers, "workers", "w", 10, "Количество параллельных воркеров")
	f.StringVarP(&cfg.OutputFile, "output", "o", "", "Файл для сохранения результатов")
	f.StringVar(&cfg.ExportFormat, "export", "txt", "Формат экспорта: txt | json | singbox | xray | nekobox")
	f.BoolVar(&cfg.OnlySuccess, "only-success", false, "Показывать только успешные результаты")
	f.Float64Var(&cfg.MinSuccessRate, "min-rate", 0.5, "Минимальный success rate для экспорта (0.0-1.0)")
	f.IntVar(&cfg.MaxPingMs, "max-ping", 3000, "Максимальный ping для включения в экспорт (мс)")
	f.BoolVarP(&cfg.Quiet, "quiet", "q", false, "Тихий режим (без прогресс-баров)")
	f.IntVar(&cfg.StabilityAttempts, "stability-attempts", 3, "Попыток для теста стабильности (режим full)")

	testCmd.MarkFlagRequired("ip")

	// --- Команда update ---
	updateCmd := &cobra.Command{
		Use:   "update",
		Short: "Обновить базу SNI-кандидатов онлайн",
		RunE:  runUpdate,
	}
	updateCmd.Flags().StringVarP(&cfg.SNIFile, "output", "o", "sni-candidates.txt", "Файл для сохранения")
	updateCmd.Flags().StringVar(&cfg.UpdateURL, "url", config.DefaultSNIListURL, "URL для загрузки")

	// --- Команда scan ---
	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Сканировать подсеть для поиска рабочих IP+SNI",
		RunE:  runScan,
	}
	scanCmd.Flags().StringVar(&cfg.SubnetScan, "subnet", "", "Подсеть CIDR, например: 1.1.1.0/24")
	scanCmd.Flags().StringVarP(&cfg.SNIFile, "sni-file", "f", "sni-candidates.txt", "Файл со списком SNI")
	scanCmd.Flags().IntVarP(&cfg.Workers, "workers", "w", 20, "Параллельных воркеров")
	scanCmd.Flags().IntVarP(&cfg.Port, "port", "p", 443, "Порт")
	scanCmd.Flags().DurationVar(&cfg.HandshakeTimeout, "timeout", 3*time.Second, "Таймаут")
	scanCmd.Flags().StringVar(&cfg.Fingerprint, "fp", "chrome", "uTLS fingerprint")
	scanCmd.MarkFlagRequired("subnet")

	root.AddCommand(testCmd, updateCmd, scanCmd)
	return root
}

// runTest — основная логика тестирования
func runTest(cmd *cobra.Command, args []string) error {
	output.PrintBanner()

	if net.ParseIP(cfg.TargetIP) == nil {
		return fmt.Errorf("неверный IP-адрес: %s", cfg.TargetIP)
	}

	sniList, err := loadSNIList()
	if err != nil {
		return err
	}

	colorInfo := color.New(color.FgCyan)
	colorInfo.Printf("  Цель:        %s:%d\n", cfg.TargetIP, cfg.Port)
	colorInfo.Printf("  SNI:         %d кандидатов\n", len(sniList))
	colorInfo.Printf("  Режим:       %s\n", cfg.Mode)
	colorInfo.Printf("  Fingerprint: %s\n", cfg.Fingerprint)
	colorInfo.Printf("  Воркеры:     %d\n", cfg.Workers)
	colorInfo.Printf("  Таймаут:     %s\n", cfg.HandshakeTimeout)
	fmt.Println()

	t := tester.NewTester(cfg.HandshakeTimeout, cfg.Fingerprint)
	startTime := time.Now()

	// --- Фаза 1: TLS Handshake ---
	color.New(color.FgMagenta, color.Bold).Println("  ▶ Фаза 1: TLS Handshake тест...")
	fmt.Println()

	results := t.TestSNIBatch(
		cfg.TargetIP,
		cfg.Port,
		sniList,
		cfg.Workers,
		func(done, total int, result *tester.HandshakeResult) {
			output.PrintProgress(done, total, result, cfg.Quiet)
		},
	)

	output.SortResults(results)
	output.PrintHandshakeTable(os.Stdout, results, cfg.OnlySuccess)
	output.PrintSummary(results, time.Since(startTime))

	// --- Фаза 2: Стабильность (только в режиме full) ---
	var stabilityMap map[string]*tester.StabilityResult

	if cfg.Mode == "full" {
		stabilityMap = runStabilityPhase(t, results)
	}

	// --- Экспорт ---
	if cfg.OutputFile != "" {
		exportPath := cfg.OutputFile
		if filepath.Ext(exportPath) == "" {
			exportPath += getDefaultExtension(cfg.ExportFormat)
		}

		err := output.ExportBest(
			results,
			stabilityMap,
			cfg.ExportFormat,
			exportPath,
			cfg.MinSuccessRate,
			cfg.MaxPingMs,
		)
		if err != nil {
			color.Red("  ✗ Ошибка экспорта: %v\n", err)
		} else {
			count := 0
			for _, r := range results {
				if r.Success && !r.BlockDetected && int(r.PingMs) <= cfg.MaxPingMs {
					count++
				}
			}
			output.PrintExportInfo(exportPath, cfg.ExportFormat, count)
		}
	} else {
		printTopSNIs(results, 10)
	}

	return nil
}

// runStabilityPhase — выполняет тест стабильности для успешных SNI
func runStabilityPhase(t *tester.Tester, results []*tester.HandshakeResult) map[string]*tester.StabilityResult {
	color.New(color.FgMagenta, color.Bold).Println("  ▶ Фаза 2: Тест стабильности...")
	fmt.Println()

	var toTest []*tester.HandshakeResult
	for _, r := range results {
		if r.Success && !r.BlockDetected {
			toTest = append(toTest, r)
		}
	}

	if len(toTest) == 0 {
		color.Yellow("  Нет успешных SNI для теста стабильности\n")
		return nil
	}

	stabilityMap := make(map[string]*tester.StabilityResult)
	stabilityResults := make([]*tester.StabilityResult, 0, len(toTest))

	for i, r := range toTest {
		if !cfg.Quiet {
			fmt.Printf("\r  Стабильность: %d/%d %-35s", i+1, len(toTest), r.SNI)
		}

		sr := t.TestStability(cfg.TargetIP, cfg.Port, r.SNI, cfg.StabilityAttempts)
		stabilityMap[r.SNI] = sr
		stabilityResults = append(stabilityResults, sr)
	}

	if !cfg.Quiet {
		fmt.Println()
	}

	output.PrintStabilityTable(os.Stdout, stabilityResults)
	return stabilityMap
}

// runUpdate — обновляет базу SNI из интернета
func runUpdate(cmd *cobra.Command, args []string) error {
	output.PrintBanner()
	color.New(color.FgCyan).Printf("  Загружаем список SNI с %s...\n", cfg.UpdateURL)

	online, err := sni.LoadFromURL(cfg.UpdateURL)
	if err != nil {
		color.Yellow("  Не удалось загрузить онлайн список: %v\n", err)
		color.Yellow("  Ничего не сохранено\n")
		return err
	}

	// Если локальный файл уже есть — мёржим, не теряем локальные правки
	if _, statErr := os.Stat(cfg.SNIFile); statErr == nil {
		local, loadErr := sni.LoadFromFile(cfg.SNIFile)
		if loadErr == nil {
			online = sni.MergeLists(local, online)
		}
	}

	if err := sni.SaveToFile(cfg.SNIFile, online); err != nil {
		return fmt.Errorf("не удалось сохранить файл: %w", err)
	}

	color.Green("  ✓ Сохранено %d SNI в файл %s\n", len(online), cfg.SNIFile)
	return nil
}

// runScan — сканирует подсеть
func runScan(cmd *cobra.Command, args []string) error {
	output.PrintBanner()

	_, ipNet, err := net.ParseCIDR(cfg.SubnetScan)
	if err != nil {
		return fmt.Errorf("неверный формат подсети: %w", err)
	}

	ips := expandCIDR(ipNet)
	color.New(color.FgCyan).Printf("  Сканируем %d IP в подсети %s...\n\n", len(ips), cfg.SubnetScan)

	sniList, err := loadSNIList()
	if err != nil {
		return err
	}

	t := tester.NewTester(cfg.HandshakeTimeout, cfg.Fingerprint)

	// При сканировании подсети берём первые 5 SNI для скорости
	testSNIs := sniList
	if len(testSNIs) > 5 {
		testSNIs = testSNIs[:5]
	}

	type scanResult struct {
		IP      string
		BestSNI string
		BestMS  int64
	}

	var bestResults []scanResult

	for idx, ip := range ips {
		if !cfg.Quiet {
			fmt.Printf("\r  IP %d/%d: %-20s", idx+1, len(ips), ip)
		}

		results := t.TestSNIBatch(ip, cfg.Port, testSNIs, cfg.Workers, nil)

		var best *tester.HandshakeResult
		for _, r := range results {
			if r.Success && !r.BlockDetected {
				if best == nil || r.PingMs < best.PingMs {
					best = r
				}
			}
		}

		if best != nil {
			bestResults = append(bestResults, scanResult{
				IP:      ip,
				BestSNI: best.SNI,
				BestMS:  best.PingMs,
			})
		}
	}

	fmt.Println()
	fmt.Println()

	if len(bestResults) == 0 {
		color.Red("  Рабочих IP с данными SNI не найдено\n")
		return nil
	}

	color.Green("  Найдено рабочих IP: %d\n\n", len(bestResults))
	for _, r := range bestResults {
		color.Green("  ✓ %-18s  SNI: %-35s  ping: %dms\n", r.IP, r.BestSNI, r.BestMS)
	}

	return nil
}

// loadSNIList — загружает список SNI, файл обязателен
func loadSNIList() ([]string, error) {
	if _, err := os.Stat(cfg.SNIFile); os.IsNotExist(err) {
		return nil, fmt.Errorf(
			"файл SNI не найден: %s\n"+
				"  Положите sni-candidates.txt рядом с бинарником\n"+
				"  или укажите путь через --sni-file",
			cfg.SNIFile,
		)
	}

	list, err := sni.LoadFromFile(cfg.SNIFile)
	if err != nil {
		return nil, fmt.Errorf("ошибка загрузки %s: %w", cfg.SNIFile, err)
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("файл %s пустой", cfg.SNIFile)
	}

	color.New(color.FgGreen).Printf("  Загружено %d SNI из %s\n", len(list), cfg.SNIFile)
	return list, nil
}

// printTopSNIs — выводит топ N лучших SNI в консоль
func printTopSNIs(results []*tester.HandshakeResult, n int) {
	color.New(color.FgMagenta, color.Bold).Printf("\n  ═══ ТОП-%d ЛУЧШИХ SNI ═══\n\n", n)

	count := 0
	for _, r := range results {
		if !r.Success || r.BlockDetected {
			continue
		}
		count++
		if count > n {
			break
		}

		certOK := "✗"
		if r.CertMatchesSNI {
			certOK = "✓"
		}

		color.Green("  %2d. %-40s  %4dms  %-7s  cert:%s\n",
			count, r.SNI, r.PingMs, r.TLSVersion, certOK)
	}

	if count == 0 {
		color.Red("  Нет успешных SNI\n")
	}

	fmt.Println()
	color.New(color.FgCyan).Println("  Для экспорта используйте флаг --output <файл> --export <формат>")
	color.New(color.FgCyan).Println("  Форматы: txt | json | singbox | xray | nekobox")
	fmt.Println()
}

// expandCIDR — раскрывает CIDR нотацию в список IP-адресов
func expandCIDR(network *net.IPNet) []string {
	var ips []string
	for ip := cloneIP(network.IP.Mask(network.Mask)); network.Contains(ip); incrementIP(ip) {
		// Пропускаем адрес сети и broadcast
		if ip[len(ip)-1] == 0 || ip[len(ip)-1] == 255 {
			continue
		}
		ips = append(ips, ip.String())
	}
	return ips
}

func cloneIP(ip net.IP) net.IP {
	clone := make(net.IP, len(ip))
	copy(clone, ip)
	return clone
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}

// getDefaultExtension — возвращает расширение файла по формату экспорта
func getDefaultExtension(format string) string {
	switch format {
	case "json", "singbox", "xray", "nekobox":
		return ".json"
	default:
		return ".txt"
	}
}