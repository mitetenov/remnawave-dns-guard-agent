// Package xraydownload is a build-only downloader for official AMD64 releases.
package xraydownload

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const asset = "Xray-linux-64.zip"
const maxArchive = 128 * 1024 * 1024

var versionPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)
var digestPattern = regexp.MustCompile(`(?im)^SHA(?:2-)?256\s*=\s*([0-9a-f]{64})\s*$`)

func DigestSHA256(text string) (string, error) {
	matches := digestPattern.FindAllStringSubmatch(text, -1)
	if len(matches) != 1 {
		return "", errors.New("invalid official SHA256 digest")
	}
	return strings.ToLower(matches[0][1]), nil
}

type Fetch func(context.Context, string, int64) ([]byte, error)

func FetchHTTPS(ctx context.Context, url string, limit int64) ([]byte, error) {
	client := &http.Client{Timeout: 120 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 || req.URL.Scheme != "https" {
			return errors.New("insecure release redirect")
		}
		return nil
	}}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	if req.URL.Scheme != "https" {
		return nil, errors.New("insecure release URL")
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, errors.New("release unavailable")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("release size limit")
	}
	return data, nil
}

func Download(ctx context.Context, version, arch, destination string, fetch Fetch) error {
	if !versionPattern.MatchString(version) || arch != "amd64" {
		return errors.New("unsupported Xray version or architecture")
	}
	url := "https://github.com/XTLS/Xray-core/releases/download/" + version + "/" + asset
	digest, err := fetch(ctx, url+".dgst", 16*1024)
	if err != nil {
		return err
	}
	expected, err := DigestSHA256(string(digest))
	if err != nil {
		return err
	}
	archive, err := fetch(ctx, url, maxArchive)
	if err != nil {
		return err
	}
	actual := sha256.Sum256(archive)
	if hex.EncodeToString(actual[:]) != expected {
		return errors.New("xray release checksum mismatch")
	}
	packageReader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return err
	}
	var binary []byte
	count := 0
	for _, file := range packageReader.File {
		if file.Name != "xray" {
			continue
		}
		count++
		if count != 1 || file.Mode()&os.ModeSymlink != 0 || file.UncompressedSize64 > maxArchive {
			return errors.New("invalid Xray archive")
		}
		reader, err := file.Open()
		if err != nil {
			return err
		}
		binary, err = io.ReadAll(io.LimitReader(reader, maxArchive+1))
		reader.Close()
		if err != nil || len(binary) == 0 || len(binary) > maxArchive {
			return errors.New("invalid Xray binary")
		}
	}
	if count != 1 {
		return errors.New("xray binary missing")
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(destination), ".xray-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err = file.Write(binary); err != nil {
		file.Close()
		return err
	}
	if err = file.Chmod(0755); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), destination)
}
