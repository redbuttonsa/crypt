package crypt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func setTestAppKey(t *testing.T) {
	t.Helper()
	key, err := GenerateAppKey()
	if err != nil {
		t.Fatalf("GenerateAppKey failed: %v", err)
	}
	t.Setenv("APP_KEY", key)
}

func generateKeyPair(t *testing.T) ([]byte, string) {
	t.Helper()

	keyStr, err := GenerateAppKey()
	if err != nil {
		t.Fatalf("GenerateAppKey failed: %v", err)
	}

	key, err := ReadAppKey(keyStr)
	if err != nil {
		t.Fatalf("ReadAppKey failed: %v", err)
	}

	return key, keyStr
}

func TestGenerateAndReadAppKey(t *testing.T) {
	setTestAppKey(t)

	key, err := GetAppKey()
	if err != nil {
		t.Fatalf("GetAppKey failed: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("Expected 32-byte key, got %d bytes", len(key))
	}
}

func TestEncryptAndDecrypt(t *testing.T) {
	setTestAppKey(t)

	plaintext := "This is a secret message."

	encrypted, err := Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if encrypted == "" {
		t.Fatal("Encrypted result is empty")
	}

	decrypted, err := Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Expected decrypted to equal original. Got: %s", decrypted)
	}
}

func TestDecryptTamperedPayloadFails(t *testing.T) {
	setTestAppKey(t)

	plaintext := "safe data"
	encrypted, err := Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	jsonRaw, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		t.Fatalf("base64 decode failed: %v", err)
	}

	var payload EncryptedPayload
	if err := json.Unmarshal(jsonRaw, &payload); err != nil {
		t.Fatalf("json unmarshal failed: %v", err)
	}

	macBytes, err := base64.StdEncoding.DecodeString(payload.MAC)
	if err != nil {
		t.Fatalf("mac decode failed: %v", err)
	}
	macBytes[0] ^= 0xFF
	payload.MAC = base64.StdEncoding.EncodeToString(macBytes)

	modifiedJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json marshal failed: %v", err)
	}
	tampered := base64.StdEncoding.EncodeToString(modifiedJSON)

	_, err = Decrypt(tampered)
	if err == nil || !strings.Contains(err.Error(), "HMAC validation failed") {
		t.Errorf("Expected HMAC validation to fail, got: %v", err)
	}
}

func TestDecryptFallsBackToPreviousKey(t *testing.T) {
	currentKey, currentKeyStr := generateKeyPair(t)
	previousKey, previousKeyStr := generateKeyPair(t)

	t.Setenv("APP_KEY", currentKeyStr)
	t.Setenv("APP_PREVIOUS_KEYS", previousKeyStr)

	oldCiphertext, err := encryptWithKey(previousKey, "rotated secret")
	if err != nil {
		t.Fatalf("encryptWithKey failed: %v", err)
	}

	decrypted, err := Decrypt(oldCiphertext)
	if err != nil {
		t.Fatalf("Decrypt failed with previous key: %v", err)
	}
	if decrypted != "rotated secret" {
		t.Fatalf("Expected decrypted text to match, got %q", decrypted)
	}

	newCiphertext, err := Encrypt("fresh secret")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if _, err := decryptWithKey(previousKey, newCiphertext); err == nil {
		t.Fatalf("Expected decryption with previous key to fail for newly encrypted payload")
	}
	if decryptedCurrent, err := decryptWithKey(currentKey, newCiphertext); err != nil || decryptedCurrent != "fresh secret" {
		t.Fatalf("Decrypt with current key failed, got value %q and err %v", decryptedCurrent, err)
	}
}

func TestDecryptFailsWhenNoKeysMatch(t *testing.T) {
	_, currentKeyStr := generateKeyPair(t)
	wrongKey, _ := generateKeyPair(t)

	t.Setenv("APP_KEY", currentKeyStr)
	t.Setenv("APP_PREVIOUS_KEYS", "")

	ciphertext, err := encryptWithKey(wrongKey, "unrecoverable")
	if err != nil {
		t.Fatalf("encryptWithKey failed: %v", err)
	}

	if _, err := Decrypt(ciphertext); err == nil {
		t.Fatal("Expected decrypt to fail when no keys match")
	}

	ciphertext, err = Encrypt("recoverable")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if decrypted, err := Decrypt(ciphertext); err != nil || decrypted != "recoverable" {
		t.Fatalf("Decrypt with current key failed, got %q and err %v", decrypted, err)
	}
}

func TestDecryptFailsOnInvalidPreviousKeys(t *testing.T) {
	_, currentKeyStr := generateKeyPair(t)
	t.Setenv("APP_KEY", currentKeyStr)
	t.Setenv("APP_PREVIOUS_KEYS", "invalid-key")

	ciphertext, err := Encrypt("data")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if _, err := Decrypt(ciphertext); err == nil || !strings.Contains(err.Error(), "failed to parse APP_PREVIOUS_KEYS") {
		t.Fatalf("Expected parse error for previous keys, got %v", err)
	}
}

func TestGetPreviousAppKeysTrimsWhitespaceAndSkipsEmpty(t *testing.T) {
	firstKey, firstKeyStr := generateKeyPair(t)
	secondKey, secondKeyStr := generateKeyPair(t)

	t.Setenv("APP_PREVIOUS_KEYS", "  "+firstKeyStr+" , , "+secondKeyStr+" , ")

	keys, err := GetPreviousAppKeys()
	if err != nil {
		t.Fatalf("GetPreviousAppKeys failed: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("Expected 2 keys, got %d", len(keys))
	}
	if !bytes.Equal(keys[0], firstKey) || !bytes.Equal(keys[1], secondKey) {
		t.Fatalf("Keys did not match input order")
	}
}
