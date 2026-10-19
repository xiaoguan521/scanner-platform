package executor

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"scanner-platform/internal/taskflow"
)

type contextInputReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextInputReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

// Trivy 0.76 accepts a Docker tar or an OCI layout directory. It does not
// accept an OCI layout tar directly. Extract only that strict layout privately;
// never extract layer contents or execute a container.
func prepareImageInput(ctx context.Context, input, destination string) (string, error) {
	file, err := os.Open(input)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() > maxSnapshotFile {
		return "", fmt.Errorf("image archive exceeds 16 GiB")
	}
	reader := tar.NewReader(contextInputReader{ctx, file})
	oci := false
	for count := 0; ; count++ {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			return input, nil // Let Trivy validate a non-OCI or compressed Docker tar.
		}
		if count >= 10000 {
			return "", fmt.Errorf("too many image archive entries")
		}
		if path.Clean(header.Name) == "oci-layout" {
			oci = true
			break
		}
	}
	if !oci {
		return input, nil
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	if err := os.Mkdir(destination, 0700); err != nil {
		return "", err
	}
	reader = tar.NewReader(contextInputReader{ctx, file})
	seen := map[string]bool{}
	var total int64
	for count := 0; ; count++ {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("read OCI archive: %w", err)
		}
		name := path.Clean(header.Name)
		if count >= 10000 || !filepath.IsLocal(filepath.FromSlash(name)) || strings.ContainsAny(name, "\\:\x00") || strings.Contains("/"+header.Name+"/", "/../") {
			return "", fmt.Errorf("unsafe OCI archive path or entry count")
		}
		if header.Typeflag == tar.TypeDir && (name == "." || name == "blobs" || name == "blobs/sha256") {
			continue
		}
		blob := strings.TrimPrefix(name, "blobs/sha256/")
		isBlob := len(blob) == 64 && blob != name
		if isBlob {
			if _, err := hex.DecodeString(blob); err != nil || blob != strings.ToLower(blob) {
				return "", fmt.Errorf("invalid OCI digest path")
			}
		}
		if (header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA) || seen[name] || (!isBlob && name != "oci-layout" && name != "index.json") || header.Size < 0 || header.Size > maxSnapshotFile {
			return "", fmt.Errorf("invalid OCI layout file, duplicate entry or link")
		}
		seen[name] = true
		total += header.Size
		if total > maxSnapshotTotal || (!isBlob && header.Size > 1<<20) {
			return "", fmt.Errorf("OCI layout exceeds size limits")
		}
		target := filepath.Join(destination, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return "", err
		}
		output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return "", err
		}
		digest := sha256.New()
		_, copyErr := io.Copy(io.MultiWriter(output, digest), reader)
		closeErr := output.Close()
		if copyErr != nil {
			return "", copyErr
		}
		if closeErr != nil {
			return "", closeErr
		}
		if isBlob && hex.EncodeToString(digest.Sum(nil)) != blob {
			return "", fmt.Errorf("OCI blob SHA-256 mismatch")
		}
	}
	if !seen["oci-layout"] || !seen["index.json"] {
		return "", fmt.Errorf("incomplete OCI layout")
	}
	var layout struct {
		Version string `json:"imageLayoutVersion"`
	}
	data, err := os.ReadFile(filepath.Join(destination, "oci-layout"))
	if err != nil || json.Unmarshal(data, &layout) != nil || layout.Version != "1.0.0" {
		return "", fmt.Errorf("invalid OCI layout version")
	}
	var index struct {
		SchemaVersion int `json:"schemaVersion"`
		Manifests     []struct {
			Digest    string `json:"digest"`
			MediaType string `json:"mediaType"`
		} `json:"manifests"`
	}
	data, err = os.ReadFile(filepath.Join(destination, "index.json"))
	if err != nil || json.Unmarshal(data, &index) != nil || index.SchemaVersion != 2 || len(index.Manifests) != 1 {
		return "", &taskflow.ExecutionError{UserMessage: "OCI 归档必须只含明确选择的一个平台镜像，请按实际工作负载镜像摘要与 CPU 平台重新导出"}
	}
	selected := index.Manifests[0]
	if (selected.MediaType != "application/vnd.oci.image.manifest.v1+json" && selected.MediaType != "application/vnd.docker.distribution.manifest.v2+json") || !strings.HasPrefix(selected.Digest, "sha256:") || !seen["blobs/sha256/"+strings.TrimPrefix(selected.Digest, "sha256:")] {
		return "", fmt.Errorf("OCI archive requires one complete image manifest")
	}
	return destination, nil
}
