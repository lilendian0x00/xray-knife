// Command compress generates the frontend files embedded by package web.
package main

import (
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

func main() {
	if err := compress(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func compress() error {
	// Build the replacement first, then swap: this also drops assets whose
	// hashed names changed in Vite.
	tmp, err := os.MkdirTemp(".", ".dist-gzip-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	if err := filepath.WalkDir("dist", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel("dist", path)
		if err != nil {
			return err
		}
		dest := filepath.Join(tmp, rel+".gz")
		if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
			return err
		}
		return compressFile(path, dest)
	}); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(tmp, "index.html.gz")); err != nil {
		return fmt.Errorf("frontend index missing: %w", err)
	}
	if err := os.RemoveAll("dist-gzip"); err != nil {
		return err
	}
	return os.Rename(tmp, "dist-gzip")
}

func compressFile(source, dest string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()
	zw, err := gzip.NewWriterLevel(out, gzip.BestCompression)
	if err != nil {
		return err
	}
	// Default empty name and zero mtime keep the output reproducible.
	if _, err := io.Copy(zw, in); err != nil {
		zw.Close()
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	return out.Close()
}
