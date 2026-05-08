package tester

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// SpeedResult — результат speed test через данный SNI
type SpeedResult struct {
	SNI string
	// Скорость загрузки в байтах/сек
	DownloadBps float64
	// Скорость отдачи в байтах/сек
	UploadBps float64
	// Ошибка (если была)
	Error string
	// Успешность теста
	Success bool
	// Время теста загрузки
	DownloadDuration time.Duration
	// Реально загружено байт
	DownloadBytes int64
}

// SpeedTester — тестер скорости через кастомный HTTP transport
type SpeedTester struct {
	Fingerprint string
	Timeout     time.Duration
	// Размер данных для теста (байт)
	TestSize int64
}

// NewSpeedTester — конструктор
func NewSpeedTester(fingerprint string, timeout time.Duration, testSize int64) *SpeedTester {
	return &SpeedTester{
		Fingerprint: fingerprint,
		Timeout:     timeout,
		TestSize:    testSize,
	}
}

// buildHTTPClient — создаёт HTTP клиент с uTLS transport,
// который подключается к указанному IP, но использует SNI из параметра.
func (st *SpeedTester) buildHTTPClient(targetIP string, port int, sni string) *http.Client {
	dialer := &net.Dialer{
		Timeout: st.Timeout,
	}

	// Кастомный DialTLSContext — всегда подключается к нашему IP,
	// независимо от того, что стоит в URL запроса
	dialTLS := func(network, addr string) (net.Conn, error) {
		targetAddr := net.JoinHostPort(targetIP, fmt.Sprintf("%d", port))
		tcpConn, err := dialer.Dial("tcp", targetAddr)
		if err != nil {
			return nil, err
		}

		tlsConfig := &utls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
		}

		clientHelloID := getClientHelloID(st.Fingerprint)
		tlsConn := utls.UClient(tcpConn, tlsConfig, clientHelloID)

		if err := tlsConn.Handshake(); err != nil {
			tcpConn.Close()
			return nil, err
		}

		return tlsConn, nil
	}

	// Пробуем HTTP/2 поверх нашего uTLS
	transport := &http.Transport{
		DialTLS:             dialTLS,
		TLSHandshakeTimeout: st.Timeout,
		ResponseHeaderTimeout: st.Timeout,
		DisableCompression:  false,
		MaxIdleConnsPerHost: 1,
	}

	// Добавляем HTTP/2 поддержку
	_ = http2.ConfigureTransport(transport)

	return &http.Client{
		Transport: transport,
		Timeout:   st.Timeout * 3,
		// Не следуем редиректам — нам нужен чистый тест
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// TestDownload — тестирует скорость загрузки через указанный SNI.
// Использует публичные speed-test endpoint'ы или Cloudflare.
func (st *SpeedTester) TestDownload(targetIP string, port int, sni string) *SpeedResult {
	result := &SpeedResult{SNI: sni}

	client := st.buildHTTPClient(targetIP, port, sni)

	// Пробуем загрузить данные с сервера через наш SNI.
	// Используем https://speed.cloudflare.com/__down?bytes=1048576 как пример
	// В реальном сценарии URL должен соответствовать SNI
	testURL := fmt.Sprintf("https://%s/__down?bytes=%d", sni, st.TestSize)

	req, err := newRequest("GET", testURL, sni)
	if err != nil {
		result.Error = fmt.Sprintf("failed to create request: %v", err)
		return result
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		result.Error = fmt.Sprintf("request failed: %v", err)
		return result
	}
	defer resp.Body.Close()

	// Читаем тело ответа, измеряя скорость
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, st.TestSize))
	result.DownloadDuration = time.Since(start)
	result.DownloadBytes = n

	if err != nil && n == 0 {
		result.Error = fmt.Sprintf("read error: %v", err)
		return result
	}

	if result.DownloadDuration.Seconds() > 0 {
		result.DownloadBps = float64(n) / result.DownloadDuration.Seconds()
	}
	result.Success = true
	return result
}

// TestTLSPing — быстрое измерение RTT через TLS (без HTTP)
func (st *SpeedTester) TestTLSPing(ip string, port int, sni string) (int64, error) {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))

	start := time.Now()

	conn, err := net.DialTimeout("tcp", addr, st.Timeout)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(st.Timeout))

	tlsConfig := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	}
	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return time.Since(start).Milliseconds(), err
	}

	return time.Since(start).Milliseconds(), nil
}

// newRequest — создаёт HTTP-запрос с реалистичными заголовками браузера
func newRequest(method, url, host string) (*http.Request, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}

	// Реалистичные заголовки Chrome
	req.Header.Set("Host", host)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	return req, nil
}