package output

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/user/sni-tester/tester"
)

// ExportResult — структура для JSON экспорта
type ExportResult struct {
	GeneratedAt string          `json:"generated_at"`
	TotalTested int             `json:"total_tested"`
	BestSNIs    []SNIExportItem `json:"best_snis"`
}

// SNIExportItem — элемент экспорта
type SNIExportItem struct {
	SNI            string  `json:"sni"`
	PingMs         int64   `json:"ping_ms"`
	TLSVersion     string  `json:"tls_version"`
	CertDomain     string  `json:"cert_domain"`
	CertMatchesSNI bool    `json:"cert_matches_sni"`
	CertIssuer     string  `json:"cert_issuer"`
	SuccessRate    float64 `json:"success_rate,omitempty"`
	Fingerprint    string  `json:"fingerprint"`
}

// ExportBest — экспортирует лучшие SNI в указанном формате
func ExportBest(
	results []*tester.HandshakeResult,
	stabilityResults map[string]*tester.StabilityResult,
	format string,
	outputFile string,
	minSuccessRate float64,
	maxPingMs int,
) error {
	// Фильтруем успешные
	var good []*tester.HandshakeResult
	for _, r := range results {
		if !r.Success || r.BlockDetected {
			continue
		}
		if int(r.PingMs) > maxPingMs {
			continue
		}
		// Проверяем success rate если есть данные стабильности
		if sr, ok := stabilityResults[r.SNI]; ok {
			if sr.SuccessRate < minSuccessRate {
				continue
			}
		}
		good = append(good, r)
	}

	// Сортируем по пингу
	sort.Slice(good, func(i, j int) bool {
		return good[i].PingMs < good[j].PingMs
	})

	if len(good) == 0 {
		return fmt.Errorf("нет подходящих SNI для экспорта")
	}

	switch strings.ToLower(format) {
	case "singbox":
		return exportSingbox(good, outputFile)
	case "xray":
		return exportXray(good, outputFile)
	case "nekobox":
		return exportNekobox(good, outputFile)
	case "json":
		return exportJSON(good, stabilityResults, outputFile)
	default:
		return exportTXT(good, stabilityResults, outputFile)
	}
}

// exportTXT — простой текстовый список SNI с рейтингом
func exportTXT(
	results []*tester.HandshakeResult,
	stability map[string]*tester.StabilityResult,
	path string,
) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Fprintf(f, "# SNI Tester — Лучшие SNI\n")
	fmt.Fprintf(f, "# Сгенерировано: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(f, "# Формат: SNI | ping | TLS | cert_ok | success_rate\n\n")

	for i, r := range results {
		rate := "—"
		if sr, ok := stability[r.SNI]; ok {
			rate = fmt.Sprintf("%.0f%%", sr.SuccessRate*100)
		}

		certOK := "no"
		if r.CertMatchesSNI {
			certOK = "yes"
		}

		fmt.Fprintf(f, "#%d %-40s | %4dms | %-7s | cert_ok=%s | rate=%s\n",
			i+1, r.SNI, r.PingMs, r.TLSVersion, certOK, rate)
		fmt.Fprintf(f, "%s\n", r.SNI)
	}

	return nil
}

// exportJSON — экспорт в JSON формат
func exportJSON(
	results []*tester.HandshakeResult,
	stability map[string]*tester.StabilityResult,
	path string,
) error {
	items := make([]SNIExportItem, 0, len(results))
	for _, r := range results {
		item := SNIExportItem{
			SNI:            r.SNI,
			PingMs:         r.PingMs,
			TLSVersion:     r.TLSVersion,
			CertDomain:     r.CertDomain,
			CertMatchesSNI: r.CertMatchesSNI,
			CertIssuer:     r.CertIssuer,
			Fingerprint:    r.Fingerprint,
		}
		if sr, ok := stability[r.SNI]; ok {
			item.SuccessRate = sr.SuccessRate
		}
		items = append(items, item)
	}

	export := ExportResult{
		GeneratedAt: time.Now().Format(time.RFC3339),
		TotalTested: len(results),
		BestSNIs:    items,
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(export)
}

// exportSingbox — экспорт в формат Sing-box outbound
func exportSingbox(results []*tester.HandshakeResult, path string) error {
	if len(results) == 0 {
		return fmt.Errorf("нет SNI для экспорта")
	}

	// Берём лучший SNI
	best := results[0]

	config := map[string]interface{}{
		"_comment":  fmt.Sprintf("SNI Tester — сгенерировано %s", time.Now().Format("2006-01-02")),
		"_best_sni": best.SNI,
		"_ping_ms":  best.PingMs,
		"outbounds": []map[string]interface{}{
			{
				"type":       "vless",
				"tag":        "vless-reality",
				"server":     "YOUR_SERVER_IP",
				"server_port": 443,
				"uuid":       "YOUR_UUID",
				"flow":       "xtls-rprx-vision",
				"tls": map[string]interface{}{
					"enabled":     true,
					"server_name": best.SNI,
					"utls": map[string]interface{}{
						"enabled":     true,
						"fingerprint": best.Fingerprint,
					},
					"reality": map[string]interface{}{
						"enabled":    true,
						"public_key": "YOUR_PUBLIC_KEY",
						"short_id":   "YOUR_SHORT_ID",
					},
				},
			},
		},
		"all_good_snis": func() []string {
			snis := make([]string, 0, len(results))
			for _, r := range results {
				snis = append(snis, r.SNI)
			}
			return snis
		}(),
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(config)
}

// exportXray — экспорт конфига для Xray-core
func exportXray(results []*tester.HandshakeResult, path string) error {
	if len(results) == 0 {
		return fmt.Errorf("нет SNI для экспорта")
	}

	best := results[0]

	sniList := make([]string, 0, len(results))
	for _, r := range results {
		sniList = append(sniList, r.SNI)
	}

	config := map[string]interface{}{
		"//": fmt.Sprintf("SNI Tester — сгенерировано %s | Лучший SNI: %s (%dms)", time.Now().Format("2006-01-02"), best.SNI, best.PingMs),
		"outbounds": []map[string]interface{}{
			{
				"tag":      "proxy",
				"protocol": "vless",
				"settings": map[string]interface{}{
					"vnext": []map[string]interface{}{
						{
							"address": "YOUR_SERVER_IP",
							"port":    443,
							"users": []map[string]interface{}{
								{
									"id":         "YOUR_UUID",
									"encryption": "none",
									"flow":       "xtls-rprx-vision",
								},
							},
						},
					},
				},
				"streamSettings": map[string]interface{}{
					"network":  "tcp",
					"security": "reality",
					"realitySettings": map[string]interface{}{
						"serverName":  best.SNI,
						"fingerprint": best.Fingerprint,
						"publicKey":   "YOUR_PUBLIC_KEY",
						"shortId":     "YOUR_SHORT_ID",
					},
				},
			},
		},
		"_tested_snis": sniList,
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(config)
}

// exportNekobox — экспорт для NekoBox (аналогично Sing-box формату)
func exportNekobox(results []*tester.HandshakeResult, path string) error {
	// NekoBox использует Sing-box ядро, формат аналогичен
	return exportSingbox(results, path)
}

// PrintExportInfo — сообщает пользователю об успешном экспорте
func PrintExportInfo(path, format string, count int) {
	fmt.Printf("\n  %s Экспортировано %d SNI в файл %s (формат: %s)\n\n",
		colorSuccess.Sprint("✓"),
		count,
		colorInfo.Sprint(path),
		colorInfo.Sprint(format),
	)
}