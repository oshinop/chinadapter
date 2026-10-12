package web

import (
	"embed"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

// staticFiles is the frontend's production build. Assets are packaged with the
// binary; the service never fetches fonts, scripts, images, telemetry, or updates
// from the network.
//
//go:embed all:static
var staticFiles embed.FS

var staticRoot fs.FS

func init() {
	staticRoot, _ = fs.Sub(staticFiles, "static")
}

func (a *API) serveAsset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		a.writeProblem(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method Not Allowed")
		return
	}
	name, spaFallback := staticAssetName(r.URL.Path)
	file, err := staticRoot.Open(name)
	if err != nil && spaFallback {
		name = "index.html"
		file, err = staticRoot.Open(name)
	}
	if err != nil {
		a.writeProblem(w, http.StatusNotFound, "not_found", "Not Found")
		return
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		a.writeProblem(w, http.StatusNotFound, "not_found", "Not Found")
		return
	}
	seeker, ok := file.(io.ReadSeeker)
	if !ok {
		a.writeProblem(w, http.StatusInternalServerError, "asset_unavailable", "Asset unavailable")
		return
	}
	if strings.HasPrefix(name, "assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		setNoStore(w.Header())
	}
	http.ServeContent(w, r, name, time.Time{}, seeker)
}

func staticAssetName(requestPath string) (name string, spaFallback bool) {
	clean := path.Clean("/" + requestPath)
	name = strings.TrimPrefix(clean, "/")
	if name == "" || name == "." {
		return "index.html", true
	}
	if strings.Contains(name, "\\") || strings.HasPrefix(name, "../") {
		return "", false
	}
	return name, !strings.Contains(path.Base(name), ".")
}
