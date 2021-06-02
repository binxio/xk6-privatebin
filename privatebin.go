package privatebin

import (
	"context"
	"encoding/base64"
	"encoding/json"

	"go.k6.io/k6/js/common"
	"go.k6.io/k6/js/modules"
)

func init() {
	modules.Register("k6/x/privatebin", new(PrivateBin))
}

type PrivateBin struct{}

type Client struct {
}

func (r *PrivateBin) XClient(ctxPtr *context.Context) interface{} {
	rt := common.GetRuntime(*ctxPtr)
	return common.Bind(rt, &Client{}, ctxPtr)
}

func (r *PrivateBin) Encrypt(payload string) string {
	pasteContent, err := json.Marshal(&PasteContent{Paste: payload})
	if err != nil {
		panic(err)
		return ""
	}

	masterKey, err := GenerateRandomBytes(32)
	if err != nil {
		panic(err)
		return ""
	}

	pasteData, err := encrypt(masterKey, pasteContent)
	if err != nil {
		panic(err)
		return ""
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

	body, err := json.Marshal(pasteRequest)
	if err != nil {
		panic(err)
		return ""
	}

	return string(body)
}
