//
// Copyright 2021 - binx.io B.V.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//
package privatebin

import (
	"encoding/base64"
	"encoding/json"
	"github.com/btcsuite/btcutil/base58"
	"math/rand"
	"time"

	"go.k6.io/k6/js/modules"
)

func init() {
	modules.Register("k6/x/privatebin", new(PrivateBin))
}

type PrivateBin struct{}

type Result struct {
	Body string
	Key  string
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

var letterRunes = []rune("\n\n\n\n\nabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func (r *PrivateBin) EncryptRandomPayload(size int, expire string) (*Result, error) {
	b := make([]rune, size)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}

	return r.Encrypt(string(b), expire)
}

func (r *PrivateBin) Encrypt(payload string, expire string) (*Result, error) {
	pasteContent, err := json.Marshal(&PasteContent{Paste: payload})
	if err != nil {
		return nil, err
	}

	masterKey, err := GenerateRandomBytes(32)
	if err != nil {
		return nil, err
	}

	pasteData, err := encrypt(masterKey, pasteContent)
	if err != nil {
		return nil, err
	}

	if expire == "" {
		expire = "1day"
	}

	pasteRequest := &PasteRequest{
		V:     2,
		AData: pasteData.adata(),
		Meta: PasteRequestMeta{
			Expire: expire,
		},
		CT: base64.RawStdEncoding.EncodeToString(pasteData.Data),
	}

	body, err := json.Marshal(pasteRequest)
	if err != nil {
		return nil, err
	}

	return &Result{Body: string(body), Key: base58.Encode(masterKey)}, nil
}
