package executor

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func privateEnv(dir string) []string {
	env := []string{"HOME=" + dir, "USERPROFILE=" + dir, "XDG_CONFIG_HOME=" + filepath.Join(dir, "config"), "XDG_CACHE_HOME=" + filepath.Join(dir, "cache"), "XDG_DATA_HOME=" + filepath.Join(dir, "data"), "TMPDIR=" + dir, "TMP=" + dir, "TEMP=" + dir}
	for _, name := range []string{"PATH", "SYSTEMROOT", "WINDIR", "JAVA_HOME"} {
		if value := os.Getenv(name); value != "" {
			env = append(env, name+"="+value)
		}
	}
	for _, name := range []string{"PUBLIC", "GITHUB", "GITLAB", "AWS", "AZURE"} {
		env = append(env, "DISABLE_NUCLEI_TEMPLATES_"+name+"_DOWNLOAD=true")
	}
	return append(env, "DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD=true", "PDCP_DISABLE_TELEMETRY=true")
}

type limitedWriter struct {
	Writer    io.Writer
	Remaining int64
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.Remaining {
		return 0, fmt.Errorf("engine output limit exceeded")
	}
	n, err := w.Writer.Write(p)
	w.Remaining -= int64(n)
	return n, err
}

func runProcess(ctx context.Context, binary string, args []string, dir string, stdout io.Writer) error {
	command := exec.CommandContext(ctx, binary, args...)
	command.Dir = dir
	command.Env = privateEnv(dir)
	command.Stdout = &limitedWriter{stdout, 32 << 20}
	log, err := os.OpenFile(filepath.Join(dir, "engine.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer log.Close()
	command.Stderr = &limitedWriter{log, 8 << 20}
	command.WaitDelay = 2 * time.Second
	configureProcess(command)
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("%s exited unsuccessfully; inspect private engine.log: %w", filepath.Base(binary), err)
	}
	return nil
}

func safeText(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 32 && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, s)
	if len(s) > n {
		s = s[:n]
	}
	return s
}
