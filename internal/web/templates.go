package web

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"path/filepath"
	"runtime"
)

type Templates struct {
	all *template.Template
}

func MustParseTemplates() *Templates {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("unable to resolve template path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	glob := filepath.Join(root, "templates", "*.html")

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
	})
	t = template.Must(t.ParseGlob(glob))
	return &Templates{all: t}
}

func (t *Templates) RenderPage(w http.ResponseWriter, data ViewData) {
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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.all.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
