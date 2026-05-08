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

// Fingerprint — тип TLS fingerprint
type Fingerprint string

const (
    FingerprintChrome  Fingerprint = "chrome"
    FingerprintFirefox Fingerprint = "firefox"
    FingerprintIOS     Fingerprint = "ios"
    FingerprintAndroid Fingerprint = "android"
    FingerprintRandom  Fingerprint = "random"
    FingerprintNone    Fingerprint = "none" // stdlib tls
)

var fingerprintMap = map[Fingerprint]*utls.ClientHelloID{
    FingerprintChrome:  &utls.HelloChrome_Auto,
    FingerprintFirefox: &utls.HelloFirefox_Auto,
    FingerprintIOS:     &utls.HelloIOS_Auto,
    FingerprintAndroid: &utls.HelloAndroid_11_OkHttp,
    FingerprintRandom:  &utls.HelloRandomizedALPN,
}

// TLSTestConfig — конфигурация одного теста
type TLSTestConfig struct {
    IP              string
    Port            int
    SNI             string
    Fingerprint     Fingerprint
    Timeout         time.Duration
    DetectBlock     bool     // проверять 16KB блок
    BlockCheckSize  int      // размер для проверки блока (байт)
}

// HandshakeTester — проводит TLS тест
type HandshakeTester struct {
    cfg TLSTestConfig
}

func NewHandshakeTester(cfg TLSTestConfig) *HandshakeTester {
    if cfg.Port == 0 {
        cfg.Port = 443
    }
    if cfg.Timeout == 0 {
        cfg.Timeout = 10 * time.Second
    }
    if cfg.BlockCheckSize == 0 {
        cfg.BlockCheckSize = 16 * 1024 // 16KB
    }
    return &HandshakeTester{cfg: cfg}
}

func (t *HandshakeTester) Run(ctx context.Context) *TestResult {
    result := &TestResult{
        SNI:         t.cfg.SNI,
        TargetIP:    t.cfg.IP,
        Port:        t.cfg.Port,
        Fingerprint: string(t.cfg.Fingerprint),
        TestedAt:    time.Now(),
    }

    addr := fmt.Sprintf("%s:%d", t.cfg.IP, t.cfg.Port)

    // TCP соединение
    dialCtx, cancel := context.WithTimeout(ctx, t.cfg.Timeout)
    defer cancel()

    dialer := &net.Dialer{}
    tcpConn, err := dialer.DialContext(dialCtx, "tcp", addr)
    if err != nil {
        result.Error = fmt.Sprintf("tcp_dial: %v", err)
        result.ComputeRating()
        return result
    }
    defer tcpConn.Close()

    // Deadline на весь handshake
    _ = tcpConn.SetDeadline(time.Now().Add(t.cfg.Timeout))

    start := time.Now()

    var certChain []*x509.Certificate

    if t.cfg.Fingerprint == FingerprintNone {
        // Стандартный crypto/tls
        tlsCfg := &tls.Config{
            ServerName:         t.cfg.SNI,
            InsecureSkipVerify: true, //nolint:gosec // намеренно
        }
        tlsConn := tls.Client(tcpConn, tlsCfg)
        if err := tlsConn.HandshakeContext(dialCtx); err != nil {
            result.Error = fmt.Sprintf("tls_handshake: %v", err)
            result.ComputeRating()
            return result
        }
        result.HandshakeTime = time.Since(start)
        result.HandshakeOK = true
        state := tlsConn.ConnectionState()
        certChain = state.PeerCertificates
        result.TLSVersion = tlsVersionStr(state.Version)

        if t.cfg.DetectBlock {
            result.BlockDetected, result.BlockReason = detectBlock(tlsConn, t.cfg.BlockCheckSize)
        }
    } else {
        // uTLS fingerprint
        helloID := utls.HelloChrome_Auto
        if id, ok := fingerprintMap[t.cfg.Fingerprint]; ok {
            helloID = *id
        }

        uConn := utls.UClient(tcpConn, &utls.Config{
            ServerName:         t.cfg.SNI,
            InsecureSkipVerify: true, //nolint:gosec
        }, helloID)

        if err := uConn.HandshakeContext(dialCtx); err != nil {
            result.Error = fmt.Sprintf("utls_handshake: %v", err)
            result.ComputeRating()
            return result
        }
        result.HandshakeTime = time.Since(start)
        result.HandshakeOK = true
        state := uConn.ConnectionState()
        certChain = state.PeerCertificates
        result.TLSVersion = tlsVersionStr(state.Version)

        if t.cfg.DetectBlock {
            result.BlockDetected, result.BlockReason = detectBlock(uConn, t.cfg.BlockCheckSize)
        }
    }

    // Анализ сертификата
    if len(certChain) > 0 {
        cert := certChain[0]
        result.CertCN = cert.Subject.CommonName
        if len(cert.Subject.Organization) > 0 {
            result.CertOrg = cert.Subject.Organization[0]
        }
        result.CertMatch = certMatchesSNI(cert, t.cfg.SNI)
    }

    result.ComputeRating()
    return result
}

// certMatchesSNI — проверяет, соответствует ли сертификат SNI
func certMatchesSNI(cert *x509.Certificate, sni string) bool {
    // Проверка CN
    if strings.EqualFold(cert.Subject.CommonName, sni) {
        return true
    }
    // Проверка wildcard CN
    if matchWildcard(cert.Subject.CommonName, sni) {
        return true
    }
    // Проверка SAN
    for _, san := range cert.DNSNames {
        if strings.EqualFold(san, sni) || matchWildcard(san, sni) {
            return true
        }
    }
    return false
}

func matchWildcard(pattern, host string) bool {
    if !strings.HasPrefix(pattern, "*.") {
        return false
    }
    suffix := pattern[1:] // ".example.com"
    return strings.HasSuffix(strings.ToLower(host), strings.ToLower(suffix))
}

func tlsVersionStr(v uint16) string {
    switch v {
    case tls.VersionTLS10:
        return "TLS 1.0"
    case tls.VersionTLS11:
        return "TLS 1.1"
    case tls.VersionTLS12:
        return "TLS 1.2"
    case tls.VersionTLS13:
        return "TLS 1.3"
    default:
        return fmt.Sprintf("0x%04x", v)
    }
}

// net.Conn-совместимый интерфейс для detectBlock
type connReader interface {
    Write(b []byte) (int, error)
    Read(b []byte) (int, error)
    SetDeadline(t time.Time) error
}

// detectBlock — отправляет HTTP GET и смотрит, не обрывает ли соединение после 16KB
func detectBlock(conn connReader, checkSize int) (blocked bool, reason string) {
    _ = conn.SetDeadline(time.Now().Add(5 * time.Second))

    // Простой HTTP/1.1 GET запрос
    req := "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n"
    if _, err := conn.Write([]byte(req)); err != nil {
        return true, "write_failed"
    }

    buf := make([]byte, checkSize+1024)
    total := 0
    for total < checkSize {
        _ = conn.SetDeadline(time.Now().Add(3 * time.Second))
        n, err := conn.Read(buf[total:])
        total += n
        if err != nil {
            if total < 100 {
                return true, "rst_after_handshake"
            }
            // Получили данные, но соединение закрылось — возможно 16KB лимит
            if total < checkSize {
                return true, fmt.Sprintf("16kb_limit_suspected_%d_bytes", total)
            }
            return false, ""
        }
    }
    return false, ""
}