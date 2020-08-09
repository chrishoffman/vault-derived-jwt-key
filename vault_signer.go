package derivedjwt

import (
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"
)

var _ crypto.Signer = (*vaultSigner)(nil)

type vaultSigner struct {
	client    *api.Client
	keyConfig *keyConfig
	publicKey ed25519.PublicKey
}

type keyConfig struct {
	mountPath string
	keyName   string
	context   []byte
}

type transitResponseKeys struct {
	PublicKey string `mapstructure:"public_key"`
}

type transitResponseData struct {
	Keys          map[int]transitResponseKeys `mapstructure:"keys"`
	LatestVersion int                         `mapstructure:"latest_version"`
}

func newVaultSigner(client *api.Client, keyConfig *keyConfig) (*vaultSigner, error) {
	// TODO: validate keyConfig

	signer := &vaultSigner{
		client:    client,
		keyConfig: keyConfig,
	}

	// get the public key...I don't love that this has to query Vault every time we need
	// to generate a new JWT
	b64Context := base64.StdEncoding.EncodeToString(signer.keyConfig.context)
	rsp, err := client.Logical().ReadWithData(signer.keyPath("keys"), map[string][]string{
		"context": {
			b64Context,
		},
	})
	if err != nil {
		return nil, err
	}

	rspData := new(transitResponseData)
	if err := mapstructure.WeakDecode(rsp.Data, rspData); err != nil {
		return nil, err
	}

	publicKey, err := base64.StdEncoding.DecodeString(rspData.Keys[rspData.LatestVersion].PublicKey)
	if err != nil {
		return nil, err
	}
	signer.publicKey = ed25519.PublicKey(publicKey)

	return signer, nil
}

func (s *vaultSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	// TODO: check if correct encoding
	b64Payload := base64.StdEncoding.EncodeToString(digest)
	b64Context := base64.StdEncoding.EncodeToString(s.keyConfig.context)

	rsp, err := s.client.Logical().Write(s.keyPath("sign"), map[string]interface{}{
		"context": b64Context,
		"input":   b64Payload,
	})
	if err != nil {
		return nil, err
	}

	sig, ok := rsp.Data["signature"]
	if !ok {
		return nil, errors.New("no signature returned")
	}
	splitSig := strings.Split(sig.(string), ":")
	if len(splitSig) != 3 {
		return nil, errors.New("malformed signature value")
	}

	sigBytes, err := base64.StdEncoding.DecodeString(splitSig[2])
	if err != nil {
		return nil, fmt.Errorf("error decoding signature: %s", err)
	}

	return sigBytes, nil
}

// this function doesn't return error, it may make sense to build this in the constructor
// since this could fail
func (s *vaultSigner) Public() crypto.PublicKey {
	return s.publicKey
}

func (s *vaultSigner) keyPath(op string) string {
	return path.Join(s.keyConfig.mountPath, op, s.keyConfig.keyName)
}
