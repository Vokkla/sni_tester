package tester

import (
	"time"
)

// StabilityResult — результат теста стабильности соединения
type StabilityResult struct {
	SNI         string
	Attempts    int
	Successes   int
	SuccessRate float64
	// Среднее время handshake по успешным попыткам
	AvgPingMs int64
	// Минимальное время
	MinPingMs int64
	// Максимальное время
	MaxPingMs int64
	// Джиттер (разброс)
	JitterMs int64
}

// TestStability — выполняет несколько попыток handshake для одного SNI
// и возвращает статистику стабильности.
func (t *Tester) TestStability(ip string, port int, sni string, attempts int) *StabilityResult {
	result := &StabilityResult{
		SNI:       sni,
		Attempts:  attempts,
		MinPingMs: int64(^uint64(0) >> 1), // MaxInt64
	}

	var pings []int64

	for i := 0; i < attempts; i++ {
		// Небольшая пауза между попытками, чтобы не триггерить rate limiting
		if i > 0 {
			time.Sleep(200 * time.Millisecond)
		}

		r := t.TestSNI(ip, port, sni)
		if r.Success && !r.BlockDetected {
			result.Successes++
			pings = append(pings, r.PingMs)

			if r.PingMs < result.MinPingMs {
				result.MinPingMs = r.PingMs
			}
			if r.PingMs > result.MaxPingMs {
				result.MaxPingMs = r.PingMs
			}
		}
	}

	if result.MinPingMs == int64(^uint64(0)>>1) {
		result.MinPingMs = 0
	}

	result.SuccessRate = float64(result.Successes) / float64(attempts)

	// Среднее и джиттер
	if len(pings) > 0 {
		var sum int64
		for _, p := range pings {
			sum += p
		}
		result.AvgPingMs = sum / int64(len(pings))

		if len(pings) > 1 {
			result.JitterMs = result.MaxPingMs - result.MinPingMs
		}
	}

	return result
}