package xraydownload

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOfficialDigestFormat(t *testing.T) {
	for _, label := range []string{"SHA2-256", "SHA256"} {
		digest, err := DigestSHA256("MD5= 123\n" + label + "= " + strings.Repeat("A", 64) + "\nSHA2-512= " + strings.Repeat("b", 128))
		if err != nil || digest != strings.Repeat("a", 64) {
			t.Fatal(digest, err)
		}
	}
	for _, text := range []string{"SHA1= " + strings.Repeat("a", 64), "SHA256= abc", "SHA256= " + strings.Repeat("a", 64) + "\nSHA2-256= " + strings.Repeat("b", 64)} {
		if _, err := DigestSHA256(text); err == nil {
			t.Fatal("accepted invalid digest", text)
		}
	}
}

func archive(t *testing.T) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	file, _ := writer.Create("xray")
	file.Write([]byte("official binary fixture"))
	writer.Close()
	return buffer.Bytes()
}

func TestVerifiedAMD64ArchiveOnly(t *testing.T) {
	data := archive(t)
	digest := sha256.Sum256(data)
	path := filepath.Join(t.TempDir(), "out", "xray")
	var urls []string
	fetch := func(_ context.Context, url string, _ int64) ([]byte, error) {
		urls = append(urls, url)
		if strings.HasSuffix(url, ".dgst") {
			return []byte(fmt.Sprintf("SHA2-256= %x", digest)), nil
		}
		return data, nil
	}
	if err := Download(context.Background(), "v26.3.27", "amd64", path, fetch); err != nil {
		t.Fatal(err)
	}
	actual, _ := os.ReadFile(path)
	info, _ := os.Stat(path)
	if string(actual) != "official binary fixture" || info.Mode().Perm() != 0755 || len(urls) != 2 {
		t.Fatal(info, urls)
	}
	for _, url := range urls {
		if !strings.HasPrefix(url, "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-64.zip") {
			t.Fatal(url)
		}
	}
	for _, arch := range []string{"arm64", "386", ""} {
		if err := Download(context.Background(), "v26.3.27", arch, path, func(context.Context, string, int64) ([]byte, error) {
			t.Fatal("unsupported build fetched release")
			return nil, nil
		}); err == nil {
			t.Fatal(arch)
		}
	}
}

func TestChecksumMismatchNeverWritesExecutable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xray")
	fetch := func(_ context.Context, url string, _ int64) ([]byte, error) {
		if strings.HasSuffix(url, ".dgst") {
			return []byte("SHA256= " + strings.Repeat("a", 64)), nil
		}
		return []byte("malicious"), nil
	}
	if err := Download(context.Background(), "v26.3.27", "amd64", path, fetch); err == nil {
		t.Fatal("checksum mismatch accepted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("unverified executable written")
	}
}
