package crypt

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeEnv(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write env: %v", err)
	}
	return path
}

func TestGenerateKeyToEnvCreatesOrUpdatesFile(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")

	key, err := GenerateKeyToEnv(envPath)
	if err != nil {
		t.Fatalf("GenerateKeyToEnv failed: %v", err)
	}
	if key == "" {
		t.Fatalf("expected generated key")
	}

	data, _ := os.ReadFile(envPath)
	if !containsLine(string(data), "APP_KEY="+key) {
		t.Fatalf("env missing APP_KEY line")
	}

	// second call replaces APP_KEY but keeps previous keys cleared
	key2, err := GenerateKeyToEnv(envPath)
	if err != nil {
		t.Fatalf("GenerateKeyToEnv second run failed: %v", err)
	}
	if key2 == key {
		t.Fatalf("expected new key")
	}
	data, _ = os.ReadFile(envPath)
	if containsLine(string(data), "APP_PREVIOUS_KEYS=") {
		t.Fatalf("APP_PREVIOUS_KEYS should not be set")
	}
}

func TestGenerateKeyToEnvRemovesPreviousKeys(t *testing.T) {
	dir := t.TempDir()
	envPath := writeEnv(t, dir, "APP_PREVIOUS_KEYS=stale\n")

	if _, err := GenerateKeyToEnv(envPath); err != nil {
		t.Fatalf("GenerateKeyToEnv failed: %v", err)
	}
	data, _ := os.ReadFile(envPath)
	if containsLine(string(data), "APP_PREVIOUS_KEYS=") {
		t.Fatalf("expected APP_PREVIOUS_KEYS to be removed")
	}
}

func TestRotateKeyInEnv(t *testing.T) {
	dir := t.TempDir()
	origKey, _ := GenerateAppKey()
	envPath := writeEnv(t, dir, "FOO=bar\nAPP_KEY="+origKey+"\nAPP_PREVIOUS_KEYS=old1\n")

	newKey, err := RotateKeyInEnv(envPath)
	if err != nil {
		t.Fatalf("RotateKeyInEnv failed: %v", err)
	}
	if newKey == origKey {
		t.Fatalf("expected new key")
	}

	data, _ := os.ReadFile(envPath)
	if !containsLine(string(data), "APP_KEY="+newKey) {
		t.Fatalf("APP_KEY not updated")
	}
	if !containsLine(string(data), "APP_PREVIOUS_KEYS="+origKey+",old1") {
		t.Fatalf("APP_PREVIOUS_KEYS not updated correctly: %s", string(data))
	}
	if !containsLine(string(data), "FOO=bar") {
		t.Fatalf("other keys should remain")
	}
}

func TestRotateKeyInEnvErrorsWithoutCurrentKey(t *testing.T) {
	dir := t.TempDir()
	envPath := writeEnv(t, dir, "FOO=bar\n")
	if _, err := RotateKeyInEnv(envPath); err == nil {
		t.Fatalf("expected error when APP_KEY missing")
	}
}

func TestRotateKeyInEnvMissingFile(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "missing.env")
	if _, err := RotateKeyInEnv(envPath); err == nil {
		t.Fatalf("expected error when APP_KEY missing")
	}
}

func TestRotateKeyInEnvWriteFailure(t *testing.T) {
	dir := t.TempDir()
	origKey, _ := GenerateAppKey()
	envPath := writeEnv(t, dir, "APP_KEY="+origKey+"\n")

	// make file read-only to force write failure
	if err := os.Chmod(envPath, 0o400); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	defer os.Chmod(envPath, 0o644)

	if _, err := RotateKeyInEnv(envPath); err == nil {
		t.Fatalf("expected write error due to permissions")
	}
}

func TestEnvFileErrorsAreSurfaced(t *testing.T) {
	// Use a directory path to trigger read/write errors.
	dir := t.TempDir()

	if _, err := GenerateKeyToEnv(dir); err == nil {
		t.Fatalf("expected error when env path is a directory")
	}
	if _, err := RotateKeyInEnv(dir); err == nil {
		t.Fatalf("expected error when env path is a directory")
	}
}

func TestReadEnvKeysMissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missing.env")
	current, previous, err := readEnvKeys(path)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if current != "" || previous != "" {
		t.Fatalf("expected empty keys for missing file")
	}
}

func TestReadEnvKeysOnlyPrevious(t *testing.T) {
	dir := t.TempDir()
	envPath := writeEnv(t, dir, "APP_PREVIOUS_KEYS=old1,old2\n")
	current, previous, err := readEnvKeys(envPath)
	if err != nil {
		t.Fatalf("readEnvKeys failed: %v", err)
	}
	if current != "" || previous != "old1,old2" {
		t.Fatalf("unexpected values: %q %q", current, previous)
	}
}

func TestReadEnvKeysSkipsCommentsAndBlankLines(t *testing.T) {
	dir := t.TempDir()
	key, _ := GenerateAppKey()
	content := "# comment line\n\nAPP_KEY=" + key + "\n#APP_PREVIOUS_KEYS=ignored\nAPP_PREVIOUS_KEYS=prev1\n"
	envPath := writeEnv(t, dir, content)

	current, previous, err := readEnvKeys(envPath)
	if err != nil {
		t.Fatalf("readEnvKeys failed: %v", err)
	}
	if current != key {
		t.Fatalf("expected current key %q, got %q", key, current)
	}
	if previous != "prev1" {
		t.Fatalf("expected previous keys, got %q", previous)
	}
}

func TestGenerateKeyToEnvRandError(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")

	orig := rand.Reader
	rand.Reader = failingReader{}
	defer func() { rand.Reader = orig }()

	if _, err := GenerateKeyToEnv(envPath); err == nil {
		t.Fatalf("expected rand failure")
	}
}

func TestRotateKeyInEnvRandError(t *testing.T) {
	dir := t.TempDir()
	origKey, _ := GenerateAppKey()
	envPath := writeEnv(t, dir, "APP_KEY="+origKey+"\n")

	orig := rand.Reader
	rand.Reader = failingReader{}
	defer func() { rand.Reader = orig }()

	if _, err := RotateKeyInEnv(envPath); err == nil {
		t.Fatalf("expected rand failure")
	}
}

func TestPrependUnique(t *testing.T) {
	cases := []struct {
		current  string
		previous string
		want     string
	}{
		{"a", "", "a"},
		{"a", "b,c", "a,b,c"},
		{"a", "a,b", "a,b"},
	}

	for _, c := range cases {
		if got := prependUnique(c.current, c.previous); got != c.want {
			t.Fatalf("prependUnique(%q,%q)=%q want %q", c.current, c.previous, got, c.want)
		}
	}
}

func TestSplitAndTrim(t *testing.T) {
	out := splitAndTrim(" a , ,b,c ")
	if len(out) != 3 || out[0] != "a" || out[1] != "b" || out[2] != "c" {
		t.Fatalf("unexpected split result: %#v", out)
	}
	if len(splitAndTrim("")) != 0 {
		t.Fatalf("expected empty slice for empty input")
	}
}

func containsLine(data, line string) bool {
	data = strings.ReplaceAll(data, "\r\n", "\n")
	for _, l := range strings.Split(data, "\n") {
		if strings.TrimSpace(l) == line {
			return true
		}
	}
	return false
}
