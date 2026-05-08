package config

import "time"

// AppVersion — текущая версия утилиты
const AppVersion = "1.0.0"

// DefaultSNIListURL — URL для обновления базы кандидатов
const DefaultSNIListURL = "https://raw.githubusercontent.com/nicholasgasior/sni-list/main/sni-list.txt"

// Config — глобальная конфигурация сессии тестирования
type Config struct {
	// Целевой IP или подсеть для подключения
	TargetIP string
	// Порт для TLS handshake (Reality/TLS обычно 443)
	Port int
	// Файл со списком SNI-кандидатов
	SNIFile string
	// Fingerprint uTLS: chrome, firefox, ios, android, safari
	Fingerprint string
	// Таймаут одного handshake
	HandshakeTimeout time.Duration
	// Количество попыток для теста стабильности
	StabilityAttempts int
	// Размер данных для speed test (байт)
	SpeedTestSize int64
	// Режим: fast | full | scan
	Mode string
	// Количество параллельных воркеров
	Workers int
	// Файл для экспорта результатов
	OutputFile string
	// Формат экспорта: singbox | xray | nekobox | json | txt
	ExportFormat string
	// Показывать только успешные результаты
	OnlySuccess bool
	// Минимальный порог успешности (0.0–1.0)
	MinSuccessRate float64
	// Максимальный TLS ping для включения в результат (мс)
	MaxPingMs int
	// URL для обновления базы SNI
	UpdateURL string
	// Диапазон подсети для режима scan
	SubnetScan string
	// Тихий режим (без прогресс-баров)
	Quiet bool
}

// DefaultConfig — значения по умолчанию
func DefaultConfig() *Config {
	return &Config{
		Port:              443,
		SNIFile:           "sni-candidates.txt",
		Fingerprint:       "chrome",
		HandshakeTimeout:  5 * time.Second,
		StabilityAttempts: 3,
		SpeedTestSize:     1 * 1024 * 1024, // 1 МБ
		Mode:              "fast",
		Workers:           10,
		ExportFormat:      "txt",
		MinSuccessRate:    0.5,
		MaxPingMs:         3000,
		UpdateURL:         DefaultSNIListURL,
		Quiet:             false,
	}
}