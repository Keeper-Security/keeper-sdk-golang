package auth

import (
	"bytes"
	"testing"

	"github.com/keeper-security/keeper-sdk-golang/api"
	"github.com/keeper-security/keeper-sdk-golang/internal/proto_auth"
)

func TestDecryptAuthHashDataKeyByPassword(t *testing.T) {
	password := "CorrectHorseBatteryStaple!"
	salt := api.GetRandomBytes(16)
	iterations := uint32(1000)
	dataKey := api.GenerateAesKey()

	encryptedDataKey, err := api.CreateEncryptionParams(password, salt, iterations, dataKey)
	if err != nil {
		t.Fatalf("CreateEncryptionParams(): %v", err)
	}

	decrypted, err := decryptAuthHashDataKey(
		proto_auth.EncryptedDataKeyType_BY_PASSWORD,
		encryptedDataKey,
		password,
		salt,
		iterations,
		nil,
	)
	if err != nil {
		t.Fatalf("decryptAuthHashDataKey(): %v", err)
	}
	if !bytes.Equal(decrypted, dataKey) {
		t.Fatal("expected decrypted data key to match original data key")
	}
}

func TestDecryptAuthHashDataKeyByAlternate(t *testing.T) {
	password := "CorrectHorseBatteryStaple!"
	salt := api.GetRandomBytes(16)
	iterations := uint32(1000)
	dataKey := api.GenerateAesKey()

	encryptionKey := api.DeriveKeyHashV2("data_key", password, salt, iterations)
	encryptedDataKey, err := api.EncryptAesV2(dataKey, encryptionKey)
	if err != nil {
		t.Fatalf("EncryptAesV2(): %v", err)
	}

	decrypted, err := decryptAuthHashDataKey(
		proto_auth.EncryptedDataKeyType_BY_ALTERNATE,
		encryptedDataKey,
		password,
		salt,
		iterations,
		nil,
	)
	if err != nil {
		t.Fatalf("decryptAuthHashDataKey(): %v", err)
	}
	if !bytes.Equal(decrypted, dataKey) {
		t.Fatal("expected decrypted data key to match original data key")
	}
}
