// Package webui embeds the built web console for sec-portable.
package webui

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed all:dist
var files embed.FS

// FileSystem returns the embedded UI, or false when the binary was built
// without running `make portable` (only the placeholder is embedded).
func FileSystem() (http.FileSystem, bool) {
	dist, err := fs.Sub(files, "dist")
	if err != nil {
		return nil, false
	}
	if _, err := fs.Stat(dist, "index.html"); err != nil {
		return nil, false
	}
	return http.FS(dist), true
}
