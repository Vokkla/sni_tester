package tester

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

// HandshakeResult — результат TLS handshake для одного SNI
type HandshakeResult struct {
	// Имя SNI, которое тестировалось
	SNI string
	// IP-адрес, к которому подключались
	IP string
	// Порт подключения
	Port int
	// Успешность handshake
	Success bool
	// Время выполнения handshake
	PingMs int64
	// Версия TLS (TLS 1.2 / TLS 1.3)
	TLSVersion string
	// Cipher suite
	CipherSuite string
	// Домен из сертификата (Subject/SAN)
	CertDomain string
	// Совпадает ли домен сертификата с SNI
	CertMatchesSNI bool
	// Эмитент сертификата
	CertIssuer string
	// Срок действия сертификата
	CertExpiry time.Time
	// Ошибка (если была)
	Error string
	// Был ли "16КБ блок" или резкий разрыв после handshake
	BlockDetected bool
	// Размер первого ответа сервера (байт)
	FirstResponseBytes int
	// Fingerprint uTLS, использованный при тесте
	Fingerprint string
}

// IsGood — возвращает true если результат пригоден для Reality dest
func (r *HandshakeResult) IsGood() bool {
	return r.Success && !r.BlockDetected && r.PingMs < 3000
}

// Tester — основной объект для выполнения TLS тестов
type Tester struct {
	// Таймаут handshake
	Timeout time.Duration
	// uTLS fingerprint
	Fingerprint string
}

// NewTester — конструктор
func NewTester(timeout time.Duration, fingerprint string) *Tester {
	return &Tester{
		Timeout:     timeout,
		Fingerprint: fingerprint,
	}
}

// getClientHelloID — конвертирует строку fingerprint в utls.ClientHelloID
func getClientHelloID(fp string) utls.ClientHelloID {
	switch strings.ToLower(fp) {
	case "chrome", "chrome120":
		return utls.HelloChrome_120
	case "firefox", "firefox120":
		return utls.HelloFirefox_120
	case "firefox105":
		return utls.HelloFirefox_105
	case "ios", "safari_ios":
		return utls.HelloIOS_14
	case "android":
		return utls.HelloAndroid_11_OkHttp
	case "safari":
		return utls.HelloSafari_16_0
	case "randomized":
		return utls.HelloRandomized
	case "randomizedalpn":
		return utls.HelloRandomizedALPN
	default:
		// По умолчанию — Chrome 120 (наиболее распространённый)
		return utls.HelloChrome_120
	}
}

// TestSNI — выполняет TLS handshake к указанному IP с данным SNI.
// Использует uTLS для имитации браузерного fingerprint.
func (t *Tester) TestSNI(ip string, port int, sni string) *HandshakeResult {
	result := &HandshakeResult{
		SNI:         sni,
		IP:          ip,
		Port:        port,
		Fingerprint: t.Fingerprint,
	}

	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))

	// Создаём контекст с таймаутом для всей операции
	ctx, cancel := context.WithTimeout(context.Background(), t.Timeout)
	defer cancel()

	start := time.Now()

	// 1. TCP-соединение
	dialer := &net.Dialer{}
	tcpConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		result.Error = fmt.Sprintf("TCP dial error: %v", err)
		result.PingMs = time.Since(start).Milliseconds()
		return result
	}
	defer tcpConn.Close()

	// Устанавливаем deadline на весь процесс
	deadline, _ := ctx.Deadline()
	tcpConn.SetDeadline(deadline)

	// 2. uTLS handshake
	tlsConfig := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // Нам важно получить сертификат, а не проверять цепочку
		MinVersion:         tls.VersionTLS12,
	}

	clientHelloID := getClientHelloID(t.Fingerprint)
	tlsConn := utls.UClient(tcpConn, tlsConfig, clientHelloID)

	if err := tlsConn.Handshake(); err != nil {
		result.Error = fmt.Sprintf("TLS handshake error: %v", err)
		result.PingMs = time.Since(start).Milliseconds()

		// Проверяем — это блокировка или обычная ошибка
		result.BlockDetected = isBlockError(err)
		return result
	}

	result.PingMs = time.Since(start).Milliseconds()
	result.Success = true

	// 3. Извлекаем информацию о сертификате
	state := tlsConn.ConnectionState()
	fillCertInfo(result, &state, sni)

	// 4. Проверка на блок после handshake:
	// Отправляем HTTP-запрос и смотрим на поведение сервера
	result.FirstResponseBytes, result.BlockDetected = checkPostHandshake(tlsConn, sni, deadline)

	return result
}

// fillCertInfo — заполняет информацию о TLS сертификате
func fillCertInfo(r *HandshakeResult, state *utls.ConnectionState, sni string) {
	// TLS версия
	switch state.Version {
	case tls.VersionTLS13:
		r.TLSVersion = "TLS 1.3"
	case tls.VersionTLS12:
		r.TLSVersion = "TLS 1.2"
	default:
		r.TLSVersion = fmt.Sprintf("TLS 0x%04x", state.Version)
	}

	// Cipher suite
	r.CipherSuite = tls.CipherSuiteName(state.CipherSuite)

	// Сертификат
	if len(state.PeerCertificates) == 0 {
		return
	}

	cert := state.PeerCertificates[0]
	r.CertExpiry = cert.NotAfter

	// Эмитент
	if len(cert.Issuer.Organization) > 0 {
		r.CertIssuer = cert.Issuer.Organization[0]
	} else {
		r.CertIssuer = cert.Issuer.CommonName
	}

	// Домен из сертификата: предпочитаем SAN, потом CN
	if len(cert.DNSNames) > 0 {
		r.CertDomain = cert.DNSNames[0]
	} else {
		r.CertDomain = cert.Subject.CommonName
	}

	// Проверяем, соответствует ли SNI сертификату
	err := cert.VerifyHostname(sni)
	r.CertMatchesSNI = err == nil

	// Дополнительная проверка по SAN
	if !r.CertMatchesSNI {
		for _, san := range cert.DNSNames {
			if matchesDomain(san, sni) {
				r.CertMatchesSNI = true
				break
			}
		}
	}
}

// matchesDomain — проверяет соответствие домена (поддерживает wildcard *.example.com)
func matchesDomain(pattern, host string) bool {
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[2:]
		// *.example.com соответствует sub.example.com, но не example.com и не a.b.example.com
		if strings.HasSuffix(host, "."+suffix) {
			sub := host[:len(host)-len(suffix)-1]
			return !strings.Contains(sub, ".")
		}
	}
	return false
}

// checkPostHandshake — отправляет HTTP HEAD запрос и проверяет ответ.
// Возвращает (количество байт первого ответа, признак блокировки).
func checkPostHandshake(conn *utls.UConn, sni string, deadline time.Time) (int, bool) {
	// Устанавливаем мягкий таймаут на чтение ответа
	readDeadline := time.Now().Add(3 * time.Second)
	if deadline.Before(readDeadline) {
		readDeadline = deadline
	}
	conn.SetReadDeadline(readDeadline)

	// Отправляем минимальный HTTP/1.1 запрос
	req := fmt.Sprintf(
		"HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\nConnection: close\r\n\r\n",
		sni,
	)

	_, err := conn.Write([]byte(req))
	if err != nil {
		// Соединение разорвано сразу после handshake — подозрительно
		return 0, true
	}

	// Читаем первые байты ответа
	buf := make([]byte, 16384) // 16КБ
	n, err := conn.Read(buf)

	if n == 0 && err != nil {
		// Никакого ответа — вероятная блокировка
		return 0, true
	}

	// Проверяем признаки блокировки в ответе
	response := string(buf[:n])
	blocked := detectBlock(response)

	return n, blocked
}

// detectBlock — анализирует HTTP-ответ на признаки блокировки
func detectBlock(response string) bool {
	// Признаки блокировки от российских операторов и DPI
	blockSignatures := []string{
		// Стандартные блок-страницы
		"Доступ ограничен",
		"Запрашиваемый ресурс заблокирован",
		"blocked",
		"BLOCKED",
		"Access Denied",
		"Forbidden by operator",
		// Редиректы на блок-страницы
		"blockpage",
		"block-page",
		"zapret",
		// Специфичные для Ростелеком, МТС, Билайн, Мегафон
		"rt.ru/block",
		"safe.beeline",
		"megafon.ru/block",
		"mts.ru/block",
		"block.mts.ru",
		// ТСПУ подписи
		"X-Forwarded-For",  // некоторые ТСПУ добавляют это в блок
		"X-Block-Reason",
	}

	for _, sig := range blockSignatures {
		if strings.Contains(response, sig) {
			return true
		}
	}

	// Проверяем: если ответ начинается не с HTTP — это тоже подозрительно,
	// но не обязательно блокировка (может быть non-HTTP сервер)
	// В данном случае не считаем это блокировкой
	return false
}

// isBlockError — определяет, является ли ошибка TLS признаком блокировки
func isBlockError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	blockIndicators := []string{
		"connection reset",
		"connection refused",
		"handshake failure",
		"unexpected message",
		"no such host", // DNS-блокировка (не должно быть при прямом IP)
		"i/o timeout",
	}
	for _, ind := range blockIndicators {
		if strings.Contains(errStr, ind) {
			return true
		}
	}
	return false
}

// TestSNIBatch — тестирует несколько SNI параллельно.
// workers — количество горутин.
// progressFn — callback для отображения прогресса (вызывается после каждого теста).
func (t *Tester) TestSNIBatch(
	ip string,
	port int,
	snis []string,
	workers int,
	progressFn func(done, total int, result *HandshakeResult),
) []*HandshakeResult {
	type job struct {
		sni string
	}

	jobs := make(chan job, len(snis))
	resultsCh := make(chan *HandshakeResult, len(snis))

	// Запускаем воркеры
	for w := 0; w < workers; w++ {
		go func() {
			for j := range jobs {
				r := t.TestSNI(ip, port, j.sni)
				resultsCh <- r
			}
		}()
	}

	// Отправляем задания
	for _, sni := range snis {
		jobs <- job{sni: sni}
	}
	close(jobs)

	// Собираем результаты
	results := make([]*HandshakeResult, 0, len(snis))
	for i := 0; i < len(snis); i++ {
		r := <-resultsCh
		results = append(results, r)
		if progressFn != nil {
			progressFn(i+1, len(snis), r)
		}
	}

	return results
}

// CheckCertChain — проверяет корректность цепочки сертификатов (для Reality dest)
func CheckCertChain(ip string, port int, sni string, timeout time.Duration) (bool, []*x509.Certificate, error) {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false, nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	tlsConf := &tls.Config{
		ServerName: sni,
		// Здесь хотим реальную проверку цепочки
		InsecureSkipVerify: false,
	}

	tlsConn := tls.Client(conn, tlsConf)
	if err := tlsConn.Handshake(); err != nil {
		return false, nil, err
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	return true, state.PeerCertificates, nil
}