package tester

import (
    "fmt"
    "time"
)

// Rating — итоговая оценка SNI
type Rating int

const (
    RatingExcellent Rating = iota // <50ms, cert match, no block
    RatingGood                    // <150ms, cert match
    RatingFair                    // handshake ok, cert mismatch
    RatingPoor                    // timeout / block detected
    RatingFailed                  // connection refused / error
)

func (r Rating) String() string {
    switch r {
    case RatingExcellent:
        return "EXCELLENT"
    case RatingGood:
        return "GOOD"
    case RatingFair:
        return "FAIR"
    case RatingPoor:
        return "POOR"
    default:
        return "FAILED"
    }
}

// TestResult — результат одного SNI теста
type TestResult struct {
    SNI             string
    TargetIP        string
    Port            int
    Fingerprint     string

    // Handshake
    HandshakeOK     bool
    HandshakeTime   time.Duration
    CertMatch       bool          // SNI совпадает с CN/SAN сертификата
    CertCN          string        // Common Name из сертификата
    CertOrg         string        // Organization
    TLSVersion      string

    // Block detection
    BlockDetected   bool
    BlockReason     string        // "rst_after_handshake", "16kb_limit", "timeout"

    // Speed test (опционально)
    SpeedTested     bool
    DownloadMbps    float64
    UploadMbps      float64

    // Stability (опционально)
    StabilityTested bool
    SuccessRate     float64       // 0.0 - 1.0
    Attempts        int

    // Итог
    Rating          Rating
    Error           string
    TestedAt        time.Time
}

func (r *TestResult) Score() int {
    if !r.HandshakeOK {
        return 0
    }
    score := 100

    // Latency
    ms := r.HandshakeTime.Milliseconds()
    switch {
    case ms < 50:
        score += 50
    case ms < 100:
        score += 30
    case ms < 200:
        score += 10
    case ms >= 500:
        score -= 30
    }

    if r.CertMatch {
        score += 20
    }
    if r.BlockDetected {
        score -= 60
    }
    if r.StabilityTested {
        score += int(r.SuccessRate * 30)
    }
    if r.SpeedTested {
        score += int(r.DownloadMbps)
    }

    return score
}

func (r *TestResult) ComputeRating() {
    if !r.HandshakeOK {
        r.Rating = RatingFailed
        return
    }
    if r.BlockDetected {
        r.Rating = RatingPoor
        return
    }
    ms := r.HandshakeTime.Milliseconds()
    switch {
    case ms < 100 && r.CertMatch:
        r.Rating = RatingExcellent
    case ms < 250:
        r.Rating = RatingGood
    default:
        r.Rating = RatingFair
    }
}

func (r *TestResult) LatencyStr() string {
    if !r.HandshakeOK {
        return "—"
    }
    return fmt.Sprintf("%dms", r.HandshakeTime.Milliseconds())
}