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
func loadSNIList(cfg *config.Config) ([]string, error) {
    if _, err := os.Stat(cfg.SNIFile); os.IsNotExist(err) {
        return nil, fmt.Errorf(
            "файл SNI не найден: %s\n"+
            "  Положите sni-candidates.txt рядом с бинарником или укажите путь через --sni-file",
            cfg.SNIFile,
        )
    }

    list, err := sni.LoadFromFile(cfg.SNIFile)
    if err != nil {
        return nil, fmt.Errorf("ошибка загрузки %s: %w", cfg.SNIFile, err)
    }
    if len(list) == 0 {
        return nil, fmt.Errorf("файл %s пустой", cfg.SNIFile)
    }

    color.New(color.FgGreen).Printf("  Загружено %d SNI из %s\n", len(list), cfg.SNIFile)
    return list, nil
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
		// Пропускаем комментарии и пустые строки
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Убираем inline-комментарии
		if idx := strings.Index(line, " #"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}
		// Дедупликация
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
		for _, sni := range list {
			lower := strings.ToLower(strings.TrimSpace(sni))
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

	for _, sni := range snis {
		fmt.Fprintln(w, sni)
	}
	return w.Flush()
}