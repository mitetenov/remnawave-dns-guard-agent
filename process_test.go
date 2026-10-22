package agent

import (
	"os"

	"path/filepath"

	"testing"
	"time"
)

func TestHeartbeatOnlyChecksProgressAndFileMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "heartbeat")
	now := time.Now()
	if Healthy(path, now) {
		t.Fatal("missing heartbeat accepted")
	}
	if err := writeHeartbeat(path, now); err != nil {
		t.Fatal(err)
	}
	if !Healthy(path, now.Add(time.Second)) {
		t.Fatal("fresh heartbeat rejected")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal(info.Mode())
	}
	if Healthy(path, now.Add(181*time.Second)) || Healthy(path, now.Add(-time.Second)) {
		t.Fatal("invalid heartbeat accepted")
	}
	if os.WriteFile(path, []byte("NaN"), 0600) != nil {
		t.Fatal("write")
	}
	if Healthy(path, now) {
		t.Fatal("NaN")
	}
	// Replacing a symlink never overwrites its target.
	target := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(target, []byte("keep"), 0600)
	os.Remove(path)
	os.Symlink(target, path)
	if err := writeHeartbeat(path, now); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(target)
	if string(data) != "keep" {
		t.Fatal("followed symlink")
	}
}
