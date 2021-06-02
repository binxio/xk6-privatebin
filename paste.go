
package privatebin

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"golang.org/x/crypto/pbkdf2"
)

const (
	specIterations  = 100000
	specKeySize     = 256
	specTagSize     = 128
	specAlgorithm   = "aes"
	specMode        = "gcm"
	specCompression = "none"
)

type PasteRequest struct {
	V     int              `json:"v"`
	AData []interface{}    `json:"adata"`
	Meta  PasteRequestMeta `json:"meta"`
	CT    string           `json:"ct"`
}

type PasteRequestMeta struct {
	Expire string `json:"expire"`
}

type PasteResponse struct {
	Status      int    `json:"status"`
	ID          string `json:"id"`
	URL         string `json:"url"`
	DeleteToken string `json:"deletetoken"`
}

type PasteContent struct {
	Paste string `json:"paste"`
}

type PasteSpec struct {
	IV          string
	Salt        string
	Iterations  int
	KeySize     int
	TagSize     int
	Algorithm   string
	Mode        string
	Compression string
}

func (spec *PasteSpec) SpecArray() []interface{} {
	return []interface{}{
		spec.IV,
		spec.Salt,
		spec.Iterations,
		spec.KeySize,
		spec.TagSize,
		spec.Algorithm,
		spec.Mode,
		spec.Compression,
	}
}

type PasteData struct {
	*PasteSpec
	Data []byte
}

func (paste *PasteData) adata() []interface{} {
	return []interface{}{
		paste.SpecArray(),
		"plaintext",
		0,
		0,
	}
}

func GenerateRandomBytes(len int) (result []byte, err error) {
	result = make([]byte, len)
	_, err = rand.Read(result)
	return result, err
}

func encrypt(master []byte, message []byte) (*PasteData, error) {
	iv, err := GenerateRandomBytes(12)
	if err != nil {
		return nil, err
	}

	salt, err := GenerateRandomBytes(8)
	if err != nil {
		return nil, err
	}

	paste := &PasteData{
		PasteSpec: &PasteSpec{
			IV:          base64.RawStdEncoding.EncodeToString(iv),
			Salt:        base64.RawStdEncoding.EncodeToString(salt),
			Iterations:  specIterations,
			KeySize:     specKeySize,
			TagSize:     specTagSize,
			Algorithm:   specAlgorithm,
			Mode:        specMode,
			Compression: specCompression,
		},
	}
	key := pbkdf2.Key(master, salt, paste.Iterations, 32, sha256.New)

	adata, err := json.Marshal(paste.adata())
	if err != nil {
		return nil, err
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	data := gcm.Seal(nil, iv, message, adata)

	paste.Data = data

	return paste, nil
}
