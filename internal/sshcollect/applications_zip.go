package sshcollect

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path"
	"strings"
	"unicode"
)

// Validate compressed Java inputs before handing them to an analyzer. Count
// actual expanded bytes as well as headers, including nested Java archives.
// Nested archives larger than 64 MiB or deeper than three are rejected.
type javaBudget struct {
	ctx     context.Context
	bytes   int64
	entries int
}

func validateJavaArchive(filename string, budget *javaBudget) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	reader, err := boundedJavaReader(file, info.Size())
	if err != nil {
		return errors.New("Java artifact is not a supported ZIP archive")
	}
	return validateJavaEntries(reader, budget, 0)
}
func validateJavaEntries(reader *zip.Reader, budget *javaBudget, depth int) error {
	if depth > 3 {
		return errors.New("nested Java archive depth exceeds limit")
	}
	seen := map[string]bool{}
	for _, entry := range reader.File {
		name := strings.TrimSuffix(entry.Name, "/")
		if name == "" || len(name) > 1024 || path.IsAbs(name) || path.Clean(name) != name || name == ".." || strings.HasPrefix(name, "../") || strings.ContainsAny(name, "\\:\x00") || seen[name] {
			return errors.New("unsafe or duplicate Java archive path")
		}
		for _, char := range name {
			if unicode.IsControl(char) {
				return errors.New("control character in Java archive path")
			}
		}
		seen[name] = true
		if budget.ctx != nil {
			if err := budget.ctx.Err(); err != nil {
				return err
			}
		}
		budget.entries++
		if budget.entries > 4096 {
			return errors.New("Java archive entry limit exceeded")
		}
		if entry.Mode()&os.ModeSymlink != 0 || !entry.FileInfo().IsDir() && !entry.Mode().IsRegular() {
			return errors.New("Java archive contains a special entry")
		}
		if entry.FileInfo().IsDir() {
			continue
		}
		if entry.UncompressedSize64 > uint64(maxApplicationTotal-budget.bytes) {
			return errors.New("expanded Java archive limit exceeded")
		}
		stream, err := entry.Open()
		if err != nil {
			return err
		}
		var nested bytes.Buffer
		var destination io.Writer = io.Discard
		ext := strings.ToLower(path.Ext(entry.Name))
		isNested := ext == ".jar" || ext == ".war" || ext == ".ear" || ext == ".par" || ext == ".zip" || ext == ".jmod"
		if isNested {
			if entry.UncompressedSize64 > 64<<20 {
				stream.Close()
				return errors.New("nested Java artifact exceeds 64 MiB")
			}
			destination = &nested
		}
		var input io.Reader = stream
		if budget.ctx != nil {
			input = &applicationReader{ctx: budget.ctx, reader: stream}
		}
		count, copyErr := io.Copy(destination, io.LimitReader(input, maxApplicationTotal-budget.bytes+1))
		closeErr := stream.Close()
		budget.bytes += count
		if copyErr != nil || closeErr != nil || budget.bytes > maxApplicationTotal || uint64(count) != entry.UncompressedSize64 {
			return errors.New("invalid or oversized expanded Java artifact")
		}
		if isNested {
			child, err := boundedJavaReader(bytes.NewReader(nested.Bytes()), int64(nested.Len()))
			if err != nil {
				return errors.New("unsupported nested Java archive")
			}
			if err := validateJavaEntries(child, budget, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// Read the small end record before archive/zip allocates its directory index.
// SSH artifacts deliberately exclude ZIP64 and multipart archives.
func boundedJavaReader(input io.ReaderAt, size int64) (*zip.Reader, error) {
	length := min(size, int64(65535+22))
	if length < 22 {
		return nil, errors.New("invalid Java ZIP archive")
	}
	tail := make([]byte, int(length))
	if _, err := input.ReadAt(tail, size-length); err != nil {
		return nil, err
	}
	valid := false
	for offset := len(tail) - 22; offset >= 0; offset-- {
		if string(tail[offset:offset+4]) != "PK\x05\x06" {
			continue
		}
		end := tail[offset:]
		if int(binary.LittleEndian.Uint16(end[20:22])) != len(end)-22 {
			continue
		}
		records := binary.LittleEndian.Uint16(end[10:12])
		directorySize := binary.LittleEndian.Uint32(end[12:16])
		if binary.LittleEndian.Uint16(end[4:6]) != 0 || binary.LittleEndian.Uint16(end[6:8]) != 0 || binary.LittleEndian.Uint16(end[8:10]) != records || records > 4096 || directorySize > 4<<20 {
			return nil, errors.New("Java ZIP directory limit exceeded")
		}
		valid = true
		break
	}
	if !valid {
		return nil, errors.New("unsupported Java ZIP end record")
	}
	return zip.NewReader(input, size)
}
