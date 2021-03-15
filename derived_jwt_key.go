package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"log"
	"path"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/api"
	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/cryptosigner"
	"gopkg.in/square/go-jose.v2/jwt"
)

func main() {
	cleanup, client := prepareTestContainer()
	defer cleanup()

	mountPath, keyName := createTransitMount(client)

	keyConfig := &keyConfig{
		mountPath: mountPath,
		keyName:   keyName,
		context:   []byte("abc"),
	}
	vaultSigner, err := newVaultSigner(client, keyConfig)
	if err != nil {
		log.Fatalf("err: %s", err)
	}

	opaqueSigner := cryptosigner.Opaque(vaultSigner)
	signingKey := jose.SigningKey{Algorithm: jose.EdDSA, Key: opaqueSigner}
	signer, err := jose.NewSigner(signingKey, nil)

	authMountPath, authRole := createJWTAuthMethod(client, vaultSigner.Public())

	// build jwt
	builder := jwt.Signed(signer)
	pubClaims := jwt.Claims{
		Issuer:   "issuer1",
		Subject:  "subject1",
		ID:       "id1",
		Audience: jwt.Audience{"aud1", "aud2"},
		IssuedAt: jwt.NewNumericDate(time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC)),
		Expiry:   jwt.NewNumericDate(time.Date(2022, 1, 1, 0, 15, 0, 0, time.UTC)),
	}
	builder = builder.Claims(pubClaims)

	// validate all ok, sign with the RSA key, and return a compact JWT
	rawJWT, err := builder.CompactSerialize()
	if err != nil {
		log.Printf("failed to create JWT: %+v", err)
	}
	log.Printf("raw jwt: %s\n", rawJWT)

	parsedJWT, err := jwt.ParseSigned(rawJWT)
	if err != nil {
		log.Fatalf("failed to parse JWT: %+v", err)
	}

	// this is the one that verifies the signature
	var claims map[string]interface{}
	if err := parsedJWT.Claims(opaqueSigner.Public(), &claims); err != nil {
		log.Fatalf("error verifying jwt: %s\n", err)
	}
	log.Printf("claims: %+v\n", claims)

	// generate a token with the auth method
	auth, err := client.Logical().Write(path.Join("auth", authMountPath, "login"), map[string]interface{}{
		"jwt":  rawJWT,
		"role": authRole,
	})
	if err != nil {
		log.Fatalf("err: %s", err)
	}
	log.Printf("token: %s", auth.Auth.ClientToken)

	rsp, err := client.Logical().Write(path.Join("auth", "token", "lookup"), map[string]interface{}{
		"token": auth.Auth.ClientToken,
	})
	if err != nil {
		log.Fatalf("err: %s", err)
	}
	log.Printf("policies: %v", rsp.Data["policies"])
}

func createTransitMount(client *api.Client) (string, string) {
	// Create transit mount
	mountPath, err := uuid.GenerateUUID()
	if err != nil {
		log.Fatalf("err: %s", err)
	}
	log.Printf("creating transit mount: %s", mountPath)
	if err := client.Sys().Mount(mountPath, &api.MountInput{
		Type: "transit",
	}); err != nil {
		log.Fatalf("Error creating vault mount: %s", err)
	}

	// Create derived signing key
	keyName, err := uuid.GenerateUUID()
	if err != nil {
		log.Fatalf("err: %s", err)
	}
	keyOptions := map[string]interface{}{
		"derived": true,
		"type":    "ed25519",
	}
	log.Printf("creating key: %s", keyName)
	_, err = client.Logical().Write(path.Join(mountPath, "keys", keyName), keyOptions)
	if err != nil {
		log.Fatalf("err: %s", err)
	}

	return mountPath, keyName
}

func createJWTAuthMethod(client *api.Client, publicKey crypto.PublicKey) (string, string) {
	// Create transit mount
	mountPath, err := uuid.GenerateUUID()
	if err != nil {
		log.Fatalf("err: %s", err)
	}
	log.Printf("creating jwt method: %s", mountPath)
	if err := client.Sys().EnableAuthWithOptions(mountPath, &api.MountInput{
		Type: "jwt",
	}); err != nil {
		log.Fatalf("Error creating vault mount: %s", err)
	}

	pKey, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		log.Fatalf("err: %s", err)
	}

	pemkey := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pKey,
	}
	pemPublicKey := pem.EncodeToMemory(pemkey)
	log.Printf("pem public key: %s", pemPublicKey)

	options := map[string]interface{}{
		"jwt_supported_algs":     []string{"EdDSA"},
		"jwt_validation_pubkeys": []string{string(pemPublicKey)},
	}
	_, err = client.Logical().Write(path.Join("auth", mountPath, "config"), options)
	if err != nil {
		log.Fatalf("err: %s", err)
	}

	// Create jwt role
	roleName, err := uuid.GenerateUUID()
	if err != nil {
		log.Fatalf("err: %s", err)
	}
	roleOptions := map[string]interface{}{
		"role_type":       "jwt",
		"user_claim":      "sub",
		"bound_audiences": []string{"aud1"},
		"token_policies":  []string{"msp", "hcp_vault"},
	}
	log.Printf("creating role: %s", roleName)
	_, err = client.Logical().Write(path.Join("auth", mountPath, "role", roleName), roleOptions)
	if err != nil {
		log.Fatalf("err: %s", err)
	}

	return mountPath, roleName
}
