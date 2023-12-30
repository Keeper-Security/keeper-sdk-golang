package api

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"go.uber.org/zap"
	"os"
	"path"
	"path/filepath"
	"strings"
)

func Base64UrlEncode(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	outLen := base64.URLEncoding.EncodedLen(len(data))
	result := make([]byte, outLen)
	base64.URLEncoding.Encode(result, data)
	for ; outLen >= 0; outLen-- {
		if result[outLen-1] != '=' {
			break
		}
	}
	return string(result[:outLen])
}

func Base64UrlDecode(text string) []byte {
	if len(text) == 0 {
		return nil
	}
	switch len(text) % 4 {
	case 0:
		break
	case 1:
		return nil
	case 2:
		text += "=="
	case 3:
		text += "="
	}
	outLen := base64.URLEncoding.DecodedLen(len(text))
	result := make([]byte, outLen)
	outLen, err := base64.URLEncoding.Decode(result, []byte(text))
	if err != nil {
		return nil
	}
	return result[:outLen]
}

func GenerateUid() []byte {
	return GetRandomBytes(16)
}

func GenerateAesKey() []byte {
	return GetRandomBytes(32)
}

func DecryptEncryptionParams(decodedParams []byte, password string) (params []byte, err error) {
	if len(decodedParams) == 100 {
		it := make([]byte, 4)
		copy(it, decodedParams[:4])
		it[0] = 0
		iterations := binary.BigEndian.Uint32(it)
		salt := decodedParams[4:20]
		encDataKey := decodedParams[20:]
		key := DeriveKeyV1(password, salt, iterations)
		var decDataKey []byte
		if decDataKey, err = DecryptAesV1Full(encDataKey, key, false); err == nil {
			if len(decDataKey) == 64 {
				if bytes.Equal(decDataKey[:32], decDataKey[32:]) {
					params = decDataKey[:32]
				} else {
					err = NewKeeperError("Invalid data key: failed mirror verification")
				}
			}
		}
	} else {
		err = NewKeeperError("Invalid encryption params: bad params length")
	}
	return
}

func CreateEncryptionParams(password string, salt []byte, iterations uint32, dataKey []byte) (encryptionParams []byte, err error) {
	encryptionParams = make([]byte, 100)
	binary.BigEndian.PutUint32(encryptionParams[:4], iterations)
	encryptionParams[0] = 1
	copy(encryptionParams[4:20], salt)
	iv := GetRandomBytes(16)
	dk := make([]byte, 64)
	copy(dk[:32], dataKey)
	copy(dk[32:], dataKey)
	key := DeriveKeyV1(password, salt, iterations)
	if encDataKey, err := EncryptAesV1Full(dk, key, iv, false); err == nil {
		copy(encryptionParams[20:], encDataKey)
	}
	return
}

func CreateAuthVerifier(password string, salt []byte, iterations uint32) string {
	data := make([]byte, 1+3+16+32)
	binary.BigEndian.PutUint32(data[:4], iterations)
	data[0] = 1
	copy(data[4:20], salt)
	key := DeriveKeyV1(password, salt, iterations)
	copy(data[20:], key)
	return Base64UrlEncode(data)
}

func GetKeeperFileFullPath(filename string) string {
	var fileFullPath string
	if strings.HasPrefix(filename, "~/") {
		home, _ := os.UserHomeDir()
		filename = filepath.Join(home, filename[2:])
	}
	info, err := os.Stat(filename)
	if err == nil {
		if !info.IsDir() {
			if fileFullPath, err = filepath.Abs(filename); err == nil {
				return fileFullPath
			}
		}
	}
	if path.IsAbs(filename) {
		return filename
	}

	if fileFullPath, err = os.UserHomeDir(); err != nil {
		GetLogger().Warn("Get User folder error", zap.Error(err))
		return filename
	}

	fileFullPath = path.Join(fileFullPath, ".keeper")
	if _, err = os.Stat(fileFullPath); err != nil {
		if os.IsNotExist(err) {
			if err = os.MkdirAll(fileFullPath, os.ModePerm); err != nil {
				GetLogger().Warn("Create Keeper folder error", zap.Error(err))
			}
		}
	}
	fileFullPath = path.Join(fileFullPath, filename)
	return fileFullPath
}

var sdkLogger *zap.Logger

func GetLogger() *zap.Logger {
	if sdkLogger == nil {
		var err error
		if sdkLogger, err = zap.NewDevelopment(); err != nil {
			sdkLogger = zap.NewNop()
		}
	}
	return sdkLogger
}
func SetNoLogger() {
	SetLogger(zap.NewNop())
}
func SetLogger(logger *zap.Logger) {
	sdkLogger = logger
}

type Set[K comparable] map[K]struct{}

func NewSet[K comparable]() Set[K] {
	return make(Set[K])
}
func MakeSet[K comparable](keys []K) Set[K] {
	var ns = NewSet[K]()
	for _, k := range keys {
		ns.Add(k)
	}
	return ns
}
func (s Set[K]) Enumerate(cb func(K) bool) {
	for k := range s {
		if !cb(k) {
			break
		}
	}
}
func (s Set[K]) Has(key K) (ok bool) {
	_, ok = s[key]
	return
}
func (s Set[K]) Add(key K) {
	s[key] = struct{}{}
}
func (s Set[K]) Delete(key K) {
	delete(s, key)
}
func (s Set[K]) ToArray() (result []K) {
	for k := range s {
		result = append(result, k)
	}
	return
}
func (s Set[K]) Copy() Set[K] {
	var ns = NewSet[K]()
	for k := range s {
		ns.Add(k)
	}
	return ns
}
func (s Set[K]) EqualTo(other Set[K]) (result bool) {
	if len(s) == len(other) {
		var ok bool
		for k := range s {
			if _, ok = other[k]; !ok {
				return
			}
		}
	}
	return true
}
func (s Set[K]) Union(other []K) {
	for _, k := range other {
		s.Add(k)
	}
}
func (s Set[K]) Intersect(other []K) {
	for _, k := range other {
		if !s.Has(k) {
			delete(s, k)
		}
	}
}
func (s Set[K]) Difference(other []K) {
	for _, k := range other {
		if s.Has(k) {
			delete(s, k)
		}
	}
}

func SliceWhere[T any](s []T, wf func(T) bool) (result []T) {
	for _, e := range s {
		if wf(e) {
			result = append(result, e)
		}
	}
	return
}

func SliceSelect[TI any, TO any](si []TI, sf func(TI) TO) (result []TO) {
	for _, e := range si {
		result = append(result, sf(e))
	}
	return
}

func SliceForeach[T any](s []T, ef func(T)) {
	for _, e := range s {
		ef(e)
	}
}

func SliceReduce[T any, A any](s []T, ini A, rf func(T, A) A) (res A) {
	res = ini
	for _, e := range s {
		res = rf(e, res)
	}
	return
}
