package privatebin

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/pbkdf2"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
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

func main() {
	// Read from STDIN (Piped input)
	input, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		panic(err)
		return
	}

	input = bytes.TrimRight(input, "\n")

	pasteContent, err := json.Marshal(&PasteContent{Paste: string(input)})
	if err != nil {
		panic(err)
		return
	}

	masterKey, err := GenerateRandomBytes(32)
	if err != nil {
		panic(err)
		return
	}

	pasteData, err := encrypt(masterKey, pasteContent)
	if err != nil {
		panic(err)
		return
	}

	// Create a new Paste Request.
	pasteRequest := &PasteRequest{
		V:     2,
		AData: pasteData.adata(),
		Meta: PasteRequestMeta{
			Expire: "1week",
		},
		CT: base64.RawStdEncoding.EncodeToString(pasteData.Data),
	}

	// Get the Request Body.
	body, err := json.Marshal(pasteRequest)
	if err != nil {
		panic(err)
		return
	}

	// Create a new HTTP Client and HTTP Request.
	client := &http.Client{}
	req, err := http.NewRequest("POST", "https://privatebin.net", bytes.NewBuffer(body))
	if err != nil {
		panic(err)
		return
	}

	// Set the request headers.
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Content-Length", strconv.Itoa(len(body)))
	req.Header.Set("X-Requested-With", "JSONHttpRequest")

	// Run the http request.
	res, err := client.Do(req)
	if err != nil {
		panic(err)
		return
	}

	// Close the request body once we are done.
	defer func() {
		err := res.Body.Close()
		if err != nil {
			panic(err)
			return
		}
	}()

	// Read the response body.
	response, err := ioutil.ReadAll(res.Body)
	if err != nil {
		panic(err)
		return
	}

	// Decode the response.
	pasteResponse := &PasteResponse{}
	err = json.Unmarshal(response, &pasteResponse)
	if err != nil {
		panic(err)
		return
	}

	fmt.Printf("%s%s#%s\n", "https://privatebin.net", pasteResponse.URL, base58.Encode(masterKey))
}

func GenerateRandomBytes(len int) (result []byte, err error) {
	result = make([]byte, len)
	_, err = rand.Read(result)
	return result, err
}

func encrypt(master []byte, message []byte) (*PasteData, error) {
	// Generate a initialization vector.
	iv, err := GenerateRandomBytes(12)
	if err != nil {
		return nil, err
	}

	// Generate salt.
	salt, err := GenerateRandomBytes(8)
	if err != nil {
		return nil, err
	}

	// Create the Paste Data and generate a key.
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
