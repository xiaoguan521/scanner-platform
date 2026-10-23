package webui

import (
	"io/fs"
	"testing"
)

func TestFileSystemReportsWhetherTheUIWasEmbedded(t *testing.T) {
	ui, ok := FileSystem()
	_, err := fs.Stat(files, "dist/index.html")
	if ok != (err == nil) {
		t.Fatalf("embedded=%t but index.html stat error=%v", ok, err)
	}
	if ok {
		index, err := ui.Open("/index.html")
		if err != nil {
			t.Fatal(err)
		}
		index.Close()
	}
}
