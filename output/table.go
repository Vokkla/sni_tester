package output

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	"github.com/Vokkla/sni_tester/tester"
)

// ColorScheme — набор цветов для вывода
var (
	colorGood    = color.New(color.FgGreen, color.Bold)
	colorOK      = color.New(color.FgYellow)
	colorBad     = color.New(color.FgRed)
	colorInfo    = color.New(color.FgCyan)
	colorHeader  = color.New(color.FgMagenta, color.Bold)
	colorSuccess = color.New(color.FgGreen)
	colorWarning = color.New(color.FgYellow, color.Bold)
	colorError   = color.New(color.FgRed, color.Bold)
)

// PrintBanner — выводит баннер приложения
func PrintBanner() {
	banner := `
 ___  _  _ _    _____        _            
/ __|| \| |_ | |_   _|___  _| |_ ___ _ _ 
\__ \| .  | |    | |/ -_)(_-_|  _/ -_) '_|
|___/|_|\_|___|  |_|\___/____|__\___||_|  
                                           
`
	colorHeader.Println(banner)
	colorInfo.Printf("  SNI Tester v1.0.0 — VLESS+Reality SNI Checker\n")
	colorInfo.Printf("  Проверяет работоспособность SNI с вашего соединения\n\n")
}

// PrintProgress — выводит строку прогресса в реальном времени
func PrintProgress(done, total int, result *tester.HandshakeResult, quiet bool) {
	if quiet {
		return
	}

	percent := int(float64(done) / float64(total) * 100)
	bar := buildProgressBar(percent, 20)

	status := ""
	if result.Success && !result.BlockDetected {
		status = colorSuccess.Sprintf("✓ %-35s %dms", result.SNI, result.PingMs)
	} else if result.BlockDetected {
		status = colorError.Sprintf("✗ %-35s BLOCKED", result.SNI)
	} else {
		errShort := result.Error
		if len(errShort) > 25 {
			errShort = errShort[:25] + "..."
		}
		status = colorBad.Sprintf("✗ %-35s %s", result.SNI, errShort)
	}

	fmt.Printf("\r  [%s] %3d%% (%d/%d) %s", bar, percent, done, total, status)
	if done == total {
		fmt.Println()
	}
}

// buildProgressBar — строит текстовый прогресс-бар
func buildProgressBar(percent, width int) string {
	filled := width * percent / 100
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	return bar
}

// SortResults — сортирует результаты по качеству (успех > ping)
func SortResults(results []*tester.HandshakeResult) {
	sort.Slice(results, func(i, j int) bool {
		ri, rj := results[i], results[j]
		// Сначала успешные без блокировки
		goodI := ri.Success && !ri.BlockDetected
		goodJ := rj.Success && !rj.BlockDetected
		if goodI != goodJ {
			return goodI
		}
		// Потом по пингу
		return ri.PingMs < rj.PingMs
	})
}

// PrintHandshakeTable — выводит таблицу результатов handshake
func PrintHandshakeTable(w io.Writer, results []*tester.HandshakeResult, onlySuccess bool) {
	if w == nil {
		w = os.Stdout
	}

	fmt.Fprintln(w)
	colorHeader.Fprintln(w, "  ═══════════════════════════════ РЕЗУЛЬТАТЫ TLS HANDSHAKE ═══════════════════════════════")
	fmt.Fprintln(w)

	table := tablewriter.NewWriter(w)
	table.SetHeader([]string{
		"#", "SNI", "СТАТУС", "PING", "TLS", "CERT DOMAIN", "CERT OK", "БЛОК", "FP",
	})

	// Настройка стиля таблицы
	table.SetBorder(true)
	table.SetRowLine(false)
	table.SetColumnSeparator("│")
	table.SetCenterSeparator("┼")
	table.SetRowSeparator("─")
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetAutoWrapText(false)
	table.SetHeaderAlignment(tablewriter.ALIGN_CENTER)

	// Цвета колонок
	table.SetColumnColor(
		tablewriter.Colors{tablewriter.Normal, tablewriter.FgCyanColor},    // #
		tablewriter.Colors{tablewriter.Bold},                                // SNI
		tablewriter.Colors{tablewriter.Bold},                                // СТАТУС
		tablewriter.Colors{tablewriter.Normal},                              // PING
		tablewriter.Colors{tablewriter.Normal, tablewriter.FgYellowColor},  // TLS
		tablewriter.Colors{tablewriter.Normal},                              // CERT DOMAIN
		tablewriter.Colors{tablewriter.Normal},                              // CERT OK
		tablewriter.Colors{tablewriter.Normal},                              // БЛОК
		tablewriter.Colors{tablewriter.Normal, tablewriter.FgMagentaColor}, // FP
	)

	num := 0
	for _, r := range results {
		if onlySuccess && (!r.Success || r.BlockDetected) {
			continue
		}

		num++

		// Статус
		var statusStr string
		var rowColors []tablewriter.Colors
		if r.Success && !r.BlockDetected {
			statusStr = "✓ OK"
			rowColors = successRowColors()
		} else if r.BlockDetected {
			statusStr = "✗ BLOCKED"
			rowColors = blockedRowColors()
		} else {
			statusStr = "✗ FAIL"
			rowColors = failRowColors()
		}

		// Пинг с цветом
		pingStr := formatPing(r.PingMs, r.Success)

		// Cert OK
		certOK := "—"
		if r.Success {
			if r.CertMatchesSNI {
				certOK = "✓"
			} else {
				certOK = "✗"
			}
		}

		// Блок
		blockStr := "—"
		if r.BlockDetected {
			blockStr = "⚠ ДА"
		} else if r.Success {
			blockStr = "нет"
		}

		// Обрезаем длинные домены
		sniDisplay := r.SNI
		if len(sniDisplay) > 35 {
			sniDisplay = sniDisplay[:32] + "..."
		}
		certDomain := r.CertDomain
		if len(certDomain) > 25 {
			certDomain = certDomain[:22] + "..."
		}

		row := []string{
			fmt.Sprintf("%d", num),
			sniDisplay,
			statusStr,
			pingStr,
			r.TLSVersion,
			certDomain,
			certOK,
			blockStr,
			r.Fingerprint,
		}

		if len(rowColors) > 0 {
			table.Rich(row, rowColors)
		} else {
			table.Append(row)
		}
	}

	table.Render()
	fmt.Fprintln(w)
}

// PrintStabilityTable — выводит таблицу результатов теста стабильности
func PrintStabilityTable(w io.Writer, results []*tester.StabilityResult) {
	if w == nil {
		w = os.Stdout
	}

	fmt.Fprintln(w)
	colorHeader.Fprintln(w, "  ═══════════════════════════════ ТЕСТ СТАБИЛЬНОСТИ ═══════════════════════════════")
	fmt.Fprintln(w)

	table := tablewriter.NewWriter(w)
	table.SetHeader([]string{
		"SNI", "УСПЕХ", "УСПЕШНОСТЬ", "AVG PING", "MIN PING", "MAX PING", "ДЖИТТЕР",
	})

	table.SetBorder(true)
	table.SetAutoWrapText(false)
	table.SetAlignment(tablewriter.ALIGN_LEFT)

	for _, r := range results {
		rateStr := fmt.Sprintf("%.0f%%", r.SuccessRate*100)

		var rateColor tablewriter.Colors
		switch {
		case r.SuccessRate >= 0.9:
			rateColor = tablewriter.Colors{tablewriter.Bold, tablewriter.FgGreenColor}
		case r.SuccessRate >= 0.6:
			rateColor = tablewriter.Colors{tablewriter.Normal, tablewriter.FgYellowColor}
		default:
			rateColor = tablewriter.Colors{tablewriter.Normal, tablewriter.FgRedColor}
		}

		row := []string{
			r.SNI,
			fmt.Sprintf("%d/%d", r.Successes, r.Attempts),
			rateStr,
			fmt.Sprintf("%dms", r.AvgPingMs),
			fmt.Sprintf("%dms", r.MinPingMs),
			fmt.Sprintf("%dms", r.MaxPingMs),
			fmt.Sprintf("%dms", r.JitterMs),
		}

		table.Rich(row, []tablewriter.Colors{
			{},
			{},
			rateColor,
			{},
			{tablewriter.FgGreenColor},
			{tablewriter.FgRedColor},
			{},
		})
	}

	table.Render()
	fmt.Fprintln(w)
}

// PrintSummary — выводит итоговую сводку
func PrintSummary(results []*tester.HandshakeResult, elapsed time.Duration) {
	total := len(results)
	success := 0
	blocked := 0
	failed := 0

	for _, r := range results {
		switch {
		case r.Success && !r.BlockDetected:
			success++
		case r.BlockDetected:
			blocked++
		default:
			failed++
		}
	}

	fmt.Println()
	colorHeader.Println("  ═══════════════════════ ИТОГИ ═══════════════════════")
	fmt.Printf("  Всего проверено:  %s\n", colorInfo.Sprintf("%d SNI", total))
	fmt.Printf("  Успешных:         %s\n", colorGood.Sprintf("%d (%.1f%%)", success, float64(success)/float64(total)*100))
	fmt.Printf("  Заблокированных:  %s\n", colorWarning.Sprintf("%d (%.1f%%)", blocked, float64(blocked)/float64(total)*100))
	fmt.Printf("  Неудачных:        %s\n", colorBad.Sprintf("%d (%.1f%%)", failed, float64(failed)/float64(total)*100))
	fmt.Printf("  Время теста:      %s\n", colorInfo.Sprintf("%.1fs", elapsed.Seconds()))
	fmt.Println()
}

// formatPing — форматирует пинг с цветовой индикацией
func formatPing(ms int64, success bool) string {
	if !success {
		return "—"
	}
	switch {
	case ms < 150:
		return colorGood.Sprintf("%dms", ms)
	case ms < 500:
		return colorOK.Sprintf("%dms", ms)
	default:
		return colorBad.Sprintf("%dms", ms)
	}
}

// Вспомогательные функции для цветных строк таблицы
func successRowColors() []tablewriter.Colors {
	return []tablewriter.Colors{
		{tablewriter.Normal, tablewriter.FgCyanColor},
		{tablewriter.Bold, tablewriter.FgGreenColor},
		{tablewriter.Bold, tablewriter.FgGreenColor},
		{tablewriter.FgGreenColor},
		{tablewriter.FgYellowColor},
		{tablewriter.Normal},
		{tablewriter.FgGreenColor},
		{tablewriter.FgGreenColor},
		{tablewriter.FgMagentaColor},
	}
}

func blockedRowColors() []tablewriter.Colors {
	return []tablewriter.Colors{
		{},
		{tablewriter.Bold, tablewriter.FgRedColor},
		{tablewriter.Bold, tablewriter.FgRedColor},
		{tablewriter.FgRedColor},
		{},
		{},
		{},
		{tablewriter.Bold, tablewriter.FgRedColor},
		{},
	}
}

func failRowColors() []tablewriter.Colors {
	return []tablewriter.Colors{
		{},
		{tablewriter.FgRedColor},
		{tablewriter.FgRedColor},
		{},
		{},
		{},
		{},
		{},
		{},
	}
}