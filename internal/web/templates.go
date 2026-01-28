package web

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type Templates struct {
	all *template.Template
}

func MustParseTemplates() *Templates {
	glob := resolveTemplateGlob()
	if glob == "" {
		panic("unable to resolve template path")
	}

	t := template.New("").Funcs(template.FuncMap{
		"dict": func(values ...any) (map[string]any, error) {
			if len(values)%2 != 0 {
				return nil, fmt.Errorf("dict requires even number of arguments")
			}
			out := make(map[string]any, len(values)/2)
			for i := 0; i < len(values); i += 2 {
				key, ok := values[i].(string)
				if !ok {
					return nil, fmt.Errorf("dict keys must be strings")
				}
				out[key] = values[i+1]
			}
			return out, nil
		},
		"safeID": func(value string) string {
			var b strings.Builder
			lastDash := false
			for _, r := range value {
				if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
					b.WriteRune(r)
					lastDash = false
					continue
				}
				if !lastDash {
					b.WriteRune('-')
					lastDash = true
				}
			}
			out := strings.Trim(b.String(), "-")
			if out == "" {
				return "note"
			}
			return out
		},
	})
	t = template.Must(t.ParseGlob(glob))
	return &Templates{all: t}
}

func resolveTemplateGlob() string {
	tryGlob := func(root string) string {
		if root == "" {
			return ""
		}
		glob := filepath.Join(root, "templates", "*.html")
		if matches, _ := filepath.Glob(glob); len(matches) > 0 {
			return glob
		}
		return ""
	}
	if cwd, err := os.Getwd(); err == nil {
		if glob := tryGlob(cwd); glob != "" {
			return glob
		}
	}
	if exe, err := os.Executable(); err == nil {
		if glob := tryGlob(filepath.Dir(exe)); glob != "" {
			return glob
		}
	}
	if _, file, _, ok := runtime.Caller(0); ok {
		root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
		if glob := tryGlob(root); glob != "" {
			return glob
		}
	}
	return ""
}

func (t *Templates) RenderPage(w http.ResponseWriter, data ViewData) {
	setNoCacheHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var content bytes.Buffer
	if err := t.all.ExecuteTemplate(&content, data.ContentTemplate, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	pageData := data
	pageData.ContentHTML = template.HTML(content.String())
	if err := t.all.ExecuteTemplate(w, "base", pageData); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (t *Templates) RenderTemplate(w http.ResponseWriter, name string, data ViewData) {
	setNoCacheHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.all.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (t *Templates) RenderTemplateWithCache(w http.ResponseWriter, name string, data ViewData, cacheControl string) {
	setCacheHeaders(w, cacheControl)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.all.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func setNoCacheHeaders(w http.ResponseWriter) {
	headers := w.Header()
	if headers.Get("Cache-Control") != "" {
		return
	}
	headers.Set("Cache-Control", "no-store")
	headers.Set("Pragma", "no-cache")
	headers.Set("Expires", "0")
}

func setCacheHeaders(w http.ResponseWriter, cacheControl string) {
	headers := w.Header()
	headers.Set("Cache-Control", cacheControl)
	headers.Del("Pragma")
	headers.Del("Expires")
}
