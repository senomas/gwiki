package e2e

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/playwright-community/playwright-go"
)

const defaultBaseURL = "http://gwiki-e2e:8080"

// login navigates to /login and authenticates using E2E_AUTH_USER / E2E_AUTH_PASS.
// If those env vars are not set, it's a no-op. If the server does not present a
// login form (e.g. auth is disabled), it returns without error.
func login(t *testing.T, page playwright.Page, baseURL string) {
	t.Helper()
	user := os.Getenv("E2E_AUTH_USER")
	pass := os.Getenv("E2E_AUTH_PASS")
	if user == "" || pass == "" {
		return
	}
	loginURL := strings.TrimRight(baseURL, "/") + "/login"
	if _, err := page.Goto(loginURL, playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilStateNetworkidle,
	}); err != nil {
		t.Fatalf("goto login: %v", err)
	}
	if !strings.Contains(page.URL(), "/login") {
		return // already authenticated or auth disabled
	}
	if err := page.Locator("input[name=\"username\"]").Fill(user); err != nil {
		t.Fatalf("fill username: %v", err)
	}
	if err := page.Locator("input[name=\"password\"]").Fill(pass); err != nil {
		t.Fatalf("fill password: %v", err)
	}
	if _, err := page.ExpectNavigation(func() error {
		return page.Locator("#login-form button[type=\"submit\"]").Click()
	}); err != nil {
		t.Fatalf("login navigation: %v", err)
	}
	if strings.Contains(page.URL(), "/login") {
		t.Fatal("login failed: still on /login after submit")
	}
}

func TestHomeSmoke(t *testing.T) {
	baseURL := os.Getenv("E2E_BASE_URL")
	if baseURL == "" {
		baseURL = defaultBaseURL
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := waitForHTTP(ctx, baseURL); err != nil {
		t.Fatalf("base url not reachable: %v", err)
	}

	pw, err := playwright.Run()
	if err != nil {
		t.Fatalf("playwright run: %v", err)
	}
	defer func() { _ = pw.Stop() }()

	browser, err := pw.Chromium.Launch()
	if err != nil {
		t.Fatalf("launch chromium: %v", err)
	}
	defer func() { _ = browser.Close() }()

	page, err := browser.NewPage()
	if err != nil {
		t.Fatalf("new page: %v", err)
	}

	login(t, page, baseURL)

	_, err = page.Goto(baseURL, playwright.PageGotoOptions{WaitUntil: playwright.WaitUntilStateNetworkidle})
	if err != nil {
		t.Fatalf("goto home: %v", err)
	}

	if err := page.Locator(".sidebar-shell").WaitFor(); err != nil {
		t.Fatalf("sidebar missing: %v", err)
	}
	if err := page.Locator(".calendar-panel").WaitFor(); err != nil {
		t.Fatalf("calendar missing: %v", err)
	}
}

func TestOpenFirstNote(t *testing.T) {
	baseURL := os.Getenv("E2E_BASE_URL")
	if baseURL == "" {
		baseURL = defaultBaseURL
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := waitForHTTP(ctx, baseURL); err != nil {
		t.Fatalf("base url not reachable: %v", err)
	}

	pw, err := playwright.Run()
	if err != nil {
		t.Fatalf("playwright run: %v", err)
	}
	defer func() { _ = pw.Stop() }()

	browser, err := pw.Chromium.Launch()
	if err != nil {
		t.Fatalf("launch chromium: %v", err)
	}
	defer func() { _ = browser.Close() }()

	page, err := browser.NewPage()
	if err != nil {
		t.Fatalf("new page: %v", err)
	}

	login(t, page, baseURL)

	_, err = page.Goto(baseURL, playwright.PageGotoOptions{WaitUntil: playwright.WaitUntilStateNetworkidle})
	if err != nil {
		t.Fatalf("goto home: %v", err)
	}

	noteLinks := page.Locator("a.js-note-actions")
	count, err := noteLinks.Count()
	if err != nil {
		t.Fatalf("count note links: %v", err)
	}
	if count == 0 {
		t.Skip("no notes available to open")
	}

	linkedTitle, err := noteLinks.First().TextContent()
	if err != nil {
		t.Fatalf("first note title: %v", err)
	}
	linkedTitle = strings.TrimSpace(linkedTitle)
	if err := noteLinks.First().Click(); err != nil {
		t.Fatalf("click first note: %v", err)
	}
	if err := page.Locator(".note-body").WaitFor(); err != nil {
		t.Fatalf("note body missing: %v", err)
	}

	detailTitle, err := page.Locator("h1 a.js-note-actions").First().TextContent()
	if err != nil {
		t.Fatalf("detail title: %v", err)
	}
	detailTitle = strings.TrimSpace(detailTitle)
	if linkedTitle != "" && detailTitle != "" && linkedTitle != detailTitle {
		t.Fatalf("title mismatch: list=%q detail=%q", linkedTitle, detailTitle)
	}

	// metadata section exists for notes that have it (root-level notes may omit it)
	if count, err := page.Locator("details.group").Count(); err == nil && count > 0 {
		if err := page.Locator("details.group").First().Locator("summary").WaitFor(); err != nil {
			t.Fatalf("metadata summary missing: %v", err)
		}
	}

	backlinks := page.Locator(".note-backlinks")
	backlinkCount, err := backlinks.Count()
	if err != nil {
		t.Fatalf("backlinks count: %v", err)
	}
	if backlinkCount > 0 {
		if err := backlinks.Locator("a[href]").First().WaitFor(); err != nil {
			t.Fatalf("backlink entry missing link: %v", err)
		}
	}
}

func waitForHTTP(ctx context.Context, rawURL string) error {
	client := &http.Client{Timeout: 2 * time.Second}
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 500 {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}
