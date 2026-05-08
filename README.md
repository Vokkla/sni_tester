# SNI Tester

Утилита для проверки работоспособности SNI через текущее интернет‑соединение.  
Используется для подбора `dest` / `server_name` в конфигурациях **VLESS + Reality**.

Инструмент проверяет не статические списки, а реальную проходимость TLS‑handshake через вашего провайдера или мобильного оператора с учётом DPI.

---

## Как это работает

Клиент отправляет TLS ClientHello с заданным SNI. DPI провайдера либо пропускает соединение, либо разрывает его.

Утилита измеряет:
- проходит ли handshake
- задержку
- стабильность соединения
- поведение после установки TLS

---

## Установка

### Сборка из исходников

```bash
git clone https://github.com/Vokkla/sni_tester.git
cd sni_tester
go mod tidy
go build -ldflags="-s -w" -o sni-tester .
```

---

## Использование

### Быстрый тест

```bash
./sni-tester test --ip 1.2.3.4
```

### Полный тест

```bash
./sni-tester test --ip 1.2.3.4 --mode full
```

### Другой порт

```bash
./sni-tester test --ip 1.2.3.4 --port 8443
```

### Fingerprint браузера

```bash
./sni-tester test --ip 1.2.3.4 --fp chrome
./sni-tester test --ip 1.2.3.4 --fp firefox
```

### Параллельность

```bash
./sni-tester test --ip 1.2.3.4 --workers 20
```

---

## SNI список

Файл: `sni-candidates.txt`

```
www.cloudflare.com
speed.cloudflare.com
www.google.com
accounts.google.com
```

---

## Экспорт

```bash
./sni-tester test --ip 1.2.3.4 --output results.txt
./sni-tester test --ip 1.2.3.4 --export json
./sni-tester test --ip 1.2.3.4 --export singbox
./sni-tester test --ip 1.2.3.4 --export xray
```

---

## Режимы

### fast
- один handshake на SNI
- быстрый отбор

### full
- повторные проверки
- анализ стабильности
- более точный результат

---

## Сканирование подсети

```bash
./sni-tester scan --subnet 1.1.1.0/24
```

---

## Критерии хорошего SNI

- handshake успешен
- нет обрывов после TLS
- низкий ping
- стабильность в full режиме

---

## Ограничения

- проверяется только TLS handshake
- результаты зависят от сети
- разные провайдеры дают разные результаты

---

## Лицензия

MIT
