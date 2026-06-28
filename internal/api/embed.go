package api

import (
	"embed"
	"io/fs"
)

//go:embed all:web_dist
var webEmbed embed.FS

// uiFS exposes the embedded web assets rooted at web_dist/.
func uiFS() fs.FS {
	sub, err := fs.Sub(webEmbed, "web_dist")
	if err != nil {
		return webEmbed
	}
	return sub
}
