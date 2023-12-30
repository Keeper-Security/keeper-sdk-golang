package api

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"golang.org/x/crypto/pbkdf2"
	"io"
)

func GetRandomBytes(size int) []byte {
	data := make([]byte, size)
	_, _ = rand.Read(data)
	return data
}

const DefaultBlockSize = 16

func pkcs7Pad(data []byte) []byte {
	n := DefaultBlockSize - (len(data) % DefaultBlockSize)
	pb := make([]byte, len(data)+n)
	copy(pb, data)
	copy(pb[len(data):], bytes.Repeat([]byte{byte(n)}, n))
	return pb
}

func pkcs7Unpad(data []byte) []byte {
	if len(data)%DefaultBlockSize == 0 {
		ch := data[len(data)-1]
		if ch <= DefaultBlockSize {
			return data[:len(data)-int(ch)]
		}
	}
	return data
}

func DecryptAesV1(data []byte, key []byte) ([]byte, error) {
	return DecryptAesV1Full(data, key, true)
}

func DecryptAesV1Full(data []byte, key []byte, usePadding bool) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	decrypter := cipher.NewCBCDecrypter(block, data[0:DefaultBlockSize])
	result := make([]byte, len(data)-DefaultBlockSize)
	if len(result)%block.BlockSize() != 0 {
		return nil, errors.New("invalid data to decrypt")
	}
	decrypter.CryptBlocks(result, data[DefaultBlockSize:])

	if usePadding {
		return pkcs7Unpad(result), nil
	}
	return result, nil
}

func EncryptAesV1(data []byte, key []byte) ([]byte, error) {
	return EncryptAesV1Full(data, key, nil, true)
}

func EncryptAesV1Full(data []byte, key []byte, iv []byte, usePadding bool) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if iv == nil {
		iv = GetRandomBytes(DefaultBlockSize)
	}
	encrypter := cipher.NewCBCEncrypter(block, iv)
	if usePadding {
		data = pkcs7Pad(data)
	}
	if len(data)%block.BlockSize() != 0 {
		return nil, errors.New("unpadded data to encrypt")
	}

	result := make([]byte, len(data)+DefaultBlockSize)
	copy(result, iv)
	encrypter.CryptBlocks(result[DefaultBlockSize:], data)
	return result, nil
}

func EncryptAesV2(data []byte, key []byte) ([]byte, error) {
	return EncryptAesV2Full(data, key, nil)
}

func EncryptAesV2Full(data []byte, key []byte, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if nonce == nil {
		nonce = GetRandomBytes(12)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	result := gcm.Seal(nonce, nonce, data, nil)
	return result, nil
}

func DecryptAesV2(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, data[:12], data[12:], nil)
}

func DeriveKeyV1(password string, salt []byte, iterations uint32) []byte {
	return pbkdf2.Key([]byte(password), salt, int(iterations), 32, sha256.New)
}

func DeriveKeyHashV1(password string, salt []byte, iterations uint32) []byte {
	key := DeriveKeyV1(password, salt, iterations)
	hash := sha256.New()
	hash.Write(key)
	return hash.Sum(nil)
}

func DeriveKeyHashV2(domain string, password string, salt []byte, iterations uint32) []byte {
	key := pbkdf2.Key([]byte(domain+password), salt, int(iterations), 64, sha512.New)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(domain))
	return mac.Sum(nil)
}

func CreateBioAuthHash(bioKey []byte) []byte {
	mac := hmac.New(sha256.New, bioKey)
	mac.Write([]byte("biometric_auth"))
	return mac.Sum(nil)
}

func LoadRsaPrivateKey(privateKeyData []byte) (privateKey *rsa.PrivateKey, err error) {
	return x509.ParsePKCS1PrivateKey(privateKeyData)
}

func UnloadRsaPrivateKey(privateKey *rsa.PrivateKey) []byte {
	return x509.MarshalPKCS1PrivateKey(privateKey)
}

func LoadRsaPublicKey(publicKey []byte) (*rsa.PublicKey, error) {
	return x509.ParsePKCS1PublicKey(publicKey)
}

func UnloadRsaPublicKey(publicKey *rsa.PublicKey) []byte {
	return x509.MarshalPKCS1PublicKey(publicKey)
}

func EncryptRsa(data []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, publicKey, data)
}

func DecryptRsa(data []byte, privateKey *rsa.PrivateKey) (result []byte, err error) {
	return rsa.DecryptPKCS1v15(rand.Reader, privateKey, data)
}

func GenerateRsaKey() (private *rsa.PrivateKey, public *rsa.PublicKey, err error) {
	if private, err = rsa.GenerateKey(rand.Reader, 2048); err == nil {
		public = &private.PublicKey
	}
	return
}

func GetRsaPublicKey(privateKey *rsa.PrivateKey) *rsa.PublicKey {
	return &privateKey.PublicKey
}

func GenerateEcKey() (private *ecdh.PrivateKey, public *ecdh.PublicKey, err error) {
	if private, err = ecdh.P256().GenerateKey(rand.Reader); err != nil {
		return
	}
	public = private.PublicKey()
	return
}

func UnloadEcPrivateKey(private *ecdh.PrivateKey) []byte {
	return private.Bytes()
}

func UnloadEcPublicKey(public *ecdh.PublicKey) []byte {
	return public.Bytes()
}

func LoadEcPrivateKey(data []byte) (*ecdh.PrivateKey, error) {
	return ecdh.P256().NewPrivateKey(data)
}

func LoadEcPublicKey(data []byte) (publicKey *ecdh.PublicKey, err error) {
	return ecdh.P256().NewPublicKey(data)
}

func GetEcPublicKey(privateKey *ecdh.PrivateKey) *ecdh.PublicKey {
	return privateKey.PublicKey()
}

func EcSharedKey(public1 *ecdh.PublicKey, private2 *ecdh.PrivateKey) (key []byte, err error) {
	if key, err = private2.ECDH(public1); err != nil {
		return
	}
	hash := sha256.New()
	hash.Write(key)
	key = hash.Sum(nil)
	return
}

func EncryptEc(data []byte, public *ecdh.PublicKey) (encrypted []byte, err error) {
	var ePrivate *ecdh.PrivateKey
	var ePublic *ecdh.PublicKey
	if ePrivate, ePublic, err = GenerateEcKey(); err == nil {
		var encryptionKey []byte
		if encryptionKey, err = EcSharedKey(public, ePrivate); err == nil {
			var encData []byte
			if encData, err = EncryptAesV2(data, encryptionKey); err == nil {
				var pubKey []byte
				if pubKey = UnloadEcPublicKey(ePublic); err == nil {
					encrypted = append(pubKey, encData...)
				}
			}
		}
	}
	return
}

func DecryptEc(data []byte, private *ecdh.PrivateKey) (decrypted []byte, err error) {
	var publicKey *ecdh.PublicKey
	if publicKey, err = LoadEcPublicKey(data[:65]); err == nil {
		var encryptionKey []byte
		if encryptionKey, err = EcSharedKey(publicKey, private); err == nil {
			decrypted, err = DecryptAesV2(data[65:], encryptionKey)
		}
	}
	return
}

type StreamCryptor interface {
	io.Reader
	GetTotal() int
}

func NewAesStreamEncryptor(reader io.Reader, key []byte) StreamCryptor {
	return newAesStreamCryptor(reader, key, true)
}
func NewAesStreamDecryptor(reader io.Reader, key []byte) StreamCryptor {
	return newAesStreamCryptor(reader, key, false)
}
func newAesStreamCryptor(reader io.Reader, key []byte, isEncrypt bool) StreamCryptor {
	var result = &streamCryptor{
		isEncrypt: isEncrypt,
		inner:     reader,
		innerErr:  nil,
		key:       key,
		buffer:    make([]byte, 10240),
		padding:   make([]byte, 0, DefaultBlockSize),
		head:      0,
		tail:      0,
		total:     0,
	}
	return result
}

type streamCryptor struct {
	isEncrypt bool
	inner     io.Reader
	innerErr  error
	key       []byte
	buffer    []byte
	padding   []byte
	head      int
	tail      int
	total     int
	crypter   cipher.BlockMode
}

func (e *streamCryptor) GetTotal() int {
	return e.total
}

func (e *streamCryptor) Read(result []byte) (read int, err error) {
	if len(result) < DefaultBlockSize {
		err = errors.New("buffer is too small")
		return
	}

	read = 0
	err = nil
	var avail int
	for len(result)-read > DefaultBlockSize {
		if (e.tail - e.head) == 0 {
			e.tail = 0
			e.head = 0
			if e.innerErr == nil {
				if len(e.padding) > 0 {
					e.tail = len(e.padding)
					copy(e.buffer, e.padding)
					e.padding = e.padding[:0]
				}
				var innerRead int
				innerRead, e.innerErr = e.inner.Read(e.buffer[e.tail:])
				if innerRead > 0 {
					e.tail += innerRead
					e.total += innerRead
				}
				bLen := e.tail - e.head
				if bLen > 0 {
					rem := bLen % DefaultBlockSize
					if rem == 0 {
						rem = DefaultBlockSize
					}
					e.padding = append(e.padding, e.buffer[e.tail-rem:e.tail]...)
					e.tail -= rem
				}
			}
		}

		if e.crypter == nil {
			var block cipher.Block
			if block, err = aes.NewCipher(e.key); err != nil {
				return
			}
			if e.isEncrypt {
				iv := GetRandomBytes(DefaultBlockSize)
				e.crypter = cipher.NewCBCEncrypter(block, iv)
				copy(result, iv)
				read += len(iv)
			} else {
				e.crypter = cipher.NewCBCDecrypter(block, e.buffer[:DefaultBlockSize])
				e.head += DefaultBlockSize
			}
			continue
		}

		fits := len(result) - read
		fits -= fits % DefaultBlockSize
		avail = e.tail - e.head
		if avail > 0 { // whole blocks
			toEncrypt := fits
			if avail < fits {
				toEncrypt = avail
			}
			e.crypter.CryptBlocks(result[read:read+toEncrypt], e.buffer[e.head:e.head+toEncrypt])
			read += toEncrypt
			e.head += toEncrypt
			continue
		} else if len(e.padding) > 0 && e.innerErr != nil {
			var unpadded []byte
			if e.isEncrypt {
				unpadded = pkcs7Pad(e.padding)
				e.padding = e.padding[:0]
				copy(e.buffer, unpadded)
				e.head = 0
				e.tail = len(unpadded)
				continue
			} else {
				copy(e.buffer, e.padding)
				e.head = 0
				e.tail = len(e.padding)
				e.crypter.CryptBlocks(e.padding, e.buffer[:e.tail])
				e.tail = 0
				unpadded = pkcs7Unpad(e.padding)
				e.padding = e.padding[:0]
				if len(unpadded) > 0 {
					copy(result[read:], unpadded)
					read += len(unpadded)
				}
			}
		}
		break
	}
	avail = e.tail - e.head
	if e.innerErr != nil && avail == 0 {
		err = e.innerErr
	}
	return
}
