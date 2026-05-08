package tester

import (
    "context"
    "crypto/tls"
    "fmt"
    "io"
    "net"
    "net/http"
    "time"

    utls "github.com/refraction-networking/utls"
    "golang.org/x/net/http2"
)

// SpeedTestConfig — конфигурация# SNI Tester — Полная реализация

## Структура проекта
