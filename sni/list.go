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

// BuiltinCandidates — встроенная база SNI кандидатов,
// актуальная для российских операторов (whitelist-friendly домены).
// Включает крупные CDN, облачные сервисы и популярные сайты.
var BuiltinCandidates = []string{
	// --- Cloudflare ---
	"www.cloudflare.com",
	"cloudflare.com",
	"blog.cloudflare.com",
	"dash.cloudflare.com",
	"api.cloudflare.com",
	"speed.cloudflare.com",
	"community.cloudflare.com",

	// --- Google ---
	"www.google.com",
	"google.com",
	"accounts.google.com",
	"mail.google.com",
	"drive.google.com",
	"photos.google.com",
	"calendar.google.com",
	"meet.google.com",
	"translate.google.com",
	"fonts.google.com",
	"fonts.gstatic.com",
	"www.gstatic.com",
	"storage.googleapis.com",
	"www.googleapis.com",
	"android.googleapis.com",

	// --- Microsoft ---
	"www.microsoft.com",
	"microsoft.com",
	"login.microsoft.com",
	"login.microsoftonline.com",
	"login.live.com",
	"outlook.live.com",
	"outlook.office.com",
	"teams.microsoft.com",
	"www.office.com",
	"onedrive.live.com",
	"azure.microsoft.com",
	"download.microsoft.com",
	"update.microsoft.com",

	// --- Apple ---
	"www.apple.com",
	"apple.com",
	"itunes.apple.com",
	"apps.apple.com",
	"icloud.com",
	"www.icloud.com",
	"appleid.apple.com",
	"developer.apple.com",
	"support.apple.com",
	"updates.cdn-apple.com",
	"swscan.apple.com",
	"ocsp.apple.com",

	// --- Amazon / AWS ---
	"aws.amazon.com",
	"console.aws.amazon.com",
	"s3.amazonaws.com",
	"ec2.amazonaws.com",
	"cloudfront.net",
	"d1.awsstatic.com",
	"amazonwebservices.com",

	// --- CDN77 / Akamai ---
	"www.akamai.com",
	"akamai.com",
	"akamaized.net",

	// --- Fastly ---
	"www.fastly.com",
	"fastly.com",
	"global.fastly.net",

	// --- Popular sites (whitelist РФ операторов) ---
	"www.wikipedia.org",
	"wikipedia.org",
	"en.wikipedia.org",
	"ru.wikipedia.org",
	"www.github.com",
	"github.com",
	"api.github.com",
	"raw.githubusercontent.com",
	"objects.githubusercontent.com",
	"www.twitch.tv",
	"twitch.tv",
	"cdn.twitch.tv",
	"discord.com",
	"www.discord.com",
	"cdn.discordapp.com",
	"gateway.discord.gg",
	"www.reddit.com",
	"reddit.com",
	"i.redd.it",
	"www.youtube.com",
	"youtube.com",
	"youtu.be",
	"ytimg.com",
	"www.netflix.com",
	"netflix.com",
	"nflxso.net",
	"www.spotify.com",
	"spotify.com",
	"open.spotify.com",
	"apresolve.spotify.com",
	"www.zoom.us",
	"zoom.us",
	"us02web.zoom.us",
	"www.dropbox.com",
	"dropbox.com",
	"dl.dropboxusercontent.com",
	"www.box.com",
	"box.com",
	"www.atlassian.com",
	"atlassian.com",
	"www.slack.com",
	"slack.com",
	"a.slack-edge.com",
	"www.notion.so",
	"notion.so",
	"www.figma.com",
	"figma.com",
	"www.canva.com",
	"canva.com",
	"www.adobe.com",
	"adobe.com",
	"creativecloud.adobe.com",

	// --- Telegram CDN ---
	"core.telegram.org",
	"cdn.telegram.org",
	"cdn1.telegram.org",
	"cdn4.telegram.org",

	// --- Misc CDN и сервисы ---
	"www.paypal.com",
	"paypal.com",
	"api.paypal.com",
	"www.twitter.com",
	"twitter.com",
	"x.com",
	"api.twitter.com",
	"www.instagram.com",
	"instagram.com",
	"cdninstagram.com",
	"www.facebook.com",
	"facebook.com",
	"static.xx.fbcdn.net",
	"www.whatsapp.com",
	"whatsapp.com",
	"web.whatsapp.com",
	"www.tiktok.com",
	"tiktok.com",
	"api16-normal-c-useast1a.tiktokv.com",
	"www.linkedin.com",
	"linkedin.com",
	"api.linkedin.com",
	"www.pinterest.com",
	"pinterest.com",
	"www.tumblr.com",
	"tumblr.com",
	"www.twilio.com",
	"twilio.com",
	"www.sendgrid.com",
	"sendgrid.com",
	"api.sendgrid.com",
	"www.mailgun.com",
	"mailgun.com",
	"www.stripe.com",
	"stripe.com",
	"api.stripe.com",
	"www.intercom.io",
	"intercom.io",
	"www.zendesk.com",
	"zendesk.com",
}

// LoadFromFile — загружает список SNI из текстового файла.
// Каждый SNI — на отдельной строке. Строки с # считаются комментарием.
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