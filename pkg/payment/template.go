package payment

import (
	"html/template"
	"io"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
)

// TemplatedPage creates a html page with the given template and meta data
func TemplatedPage(w io.Writer, meta interface{}, p string) error {
	l := log.WithFields(log.Fields{
		"action": "TemplatedPage",
		"meta":   meta,
		"p":      p,
	})
	l.Info("start")
	//lp := filepath.Join("static", "layout.html")
	fp := filepath.Join("static", filepath.Clean(p))

	// Return a 404 if the template doesn't exist
	info, err := os.Stat(fp)
	if err != nil {
		l.WithError(err).Errorf("Failed to stat file: %s", fp)
		if os.IsNotExist(err) {
			l.Errorf("File does not exist: %s", fp)
			return err
		}
	}

	// Return a 404 if the request is for a directory
	if info.IsDir() {
		l.Errorf("Request is for a directory: %s", fp)
		return err
	}

	tmpl, err := template.ParseGlob("static/*")
	if err != nil {
		l.WithError(err).Errorf("Failed to parse template: %s", fp)
		return err
	}

	err = tmpl.ExecuteTemplate(w, "layout", meta)
	if err != nil {
		l.WithError(err).Errorf("Failed to execute template: %s", fp)
		return err
	}
	return nil
}
