package sni

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// LoadFromFile — загружает список SNI из текстового файла.
// Каждый SNI на отдельной строке, строки с # — комментарии.
func LoadFromFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("не удалось открыть файл %s: %w", path, err)
	}
	defer f.Close()

	return parseLines(f), nil
}

// LoadFromURL — скачивает список SNI по указанному URL.
func LoadFromURL(url string) ([]string, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("не удалось загрузить список с %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d при загрузке %s", resp.StatusCode, url)
	}

	return parseLines(resp.Body), nil
}

// parseLines — разбирает строки из ридера, пропуская комментарии и пустые строки.
func parseLines(r io.Reader) []string {
	var result []string
	scanner := bufio.NewScanner(r)
	seen := make(map[string]bool)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Убираем inline-комментарии вида: example.com # пояснение
		if idx := strings.Index(line, " #"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}
		lower := strings.ToLower(line)
		if !seen[lower] {
			seen[lower] = true
			result = append(result, lower)
		}
	}
	return result
}

// MergeLists — объединяет несколько списков SNI с дедупликацией.
func MergeLists(lists ...[]string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, list := range lists {
		for _, s := range list {
			lower := strings.ToLower(strings.TrimSpace(s))
			if lower != "" && !seen[lower] {
				seen[lower] = true
				result = append(result, lower)
			}
		}
	}
	return result
}

// SaveToFile — сохраняет список SNI в файл.
func SaveToFile(path string, snis []string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("не удалось создать файл %s: %w", path, err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	fmt.Fprintf(w, "# SNI Candidates — обновлено: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintln(w, "# Формат: один SNI на строку, строки с # — комментарии")
	fmt.Fprintln(w)

	for _, s := range snis {
		fmt.Fprintln(w, s)
	}
	return w.Flush()
}