package derivedjwt

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"runtime"
	"testing"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/api"
	"github.com/ory/dockertest/v3"
	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/cryptosigner"
	"gopkg.in/square/go-jose.v2/jwt"
)

func TestDerivedKey(t *testing.T) {
	cleanup, client := prepareTestContainer(t)
	defer cleanup()

	mountPath, keyName := createTransitMount(t, client)

	keyConfig := &keyConfig{
		mountPath: mountPath,
		keyName:   keyName,
		context:   []byte("abc"),
	}
	vaultSigner, err := newVaultSigner(client, keyConfig)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	opaqueSigner := cryptosigner.Opaque(vaultSigner)
	signingKey := jose.SigningKey{Algorithm: jose.EdDSA, Key: opaqueSigner}
	signer, err := jose.NewSigner(signingKey, nil)

	// build jwt
	builder := jwt.Signed(signer)
	pubClaims := jwt.Claims{
		Issuer:   "issuer1",
		Subject:  "subject1",
		ID:       "id1",
		Audience: jwt.Audience{"aud1", "aud2"},
		IssuedAt: jwt.NewNumericDate(time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC)),
		Expiry:   jwt.NewNumericDate(time.Date(2017, 1, 1, 0, 15, 0, 0, time.UTC)),
	}
	builder = builder.Claims(pubClaims)

	// validate all ok, sign with the RSA key, and return a compact JWT
	rawJWT, err := builder.CompactSerialize()
	if err != nil {
		log.Fatalf("failed to create JWT: %+v", err)
	}
	t.Logf("raw jwt: %s", rawJWT)

	parsedJWT, err := jwt.ParseSigned(rawJWT)
	if err != nil {
		log.Fatalf("failed to parse JWT: %+v", err)
	}

	// this is the one that verifies the signature
	var claims map[string]interface{}
	if err := parsedJWT.Claims(opaqueSigner.Public(), &claims); err != nil {
		t.Fatalf("error verifying jwt: %s", err)
	}
	t.Logf("claims: %+v", claims)
}

func createTransitMount(t *testing.T, client *api.Client) (string, string) {
	// Create transit mount
	mountPath, err := uuid.GenerateUUID()
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	t.Logf("creating transit mount: %s", mountPath)
	if err := client.Sys().Mount(mountPath, &api.MountInput{
		Type: "transit",
	}); err != nil {
		t.Fatalf("Error creating vault mount: %s", err)
	}

	// Create derived signing key
	keyName, err := uuid.GenerateUUID()
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	keyOptions := map[string]interface{}{
		"derived": true,
		"type":    "ed25519",
	}
	t.Logf("creating key: %s", keyName)
	_, err = client.Logical().Write(path.Join(mountPath, "keys", keyName), keyOptions)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	return mountPath, keyName
}

func prepareTestContainer(t *testing.T) (func(), *api.Client) {
	testToken, err := uuid.GenerateUUID()
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	t.Logf("generating test token: %s", testToken)

	var tempDir string
	// Docker for Mac does not play nice with TempDir
	if runtime.GOOS == "darwin" {
		uniqueTempDir, err := uuid.GenerateUUID()
		if err != nil {
			t.Fatalf("err: %s", err)
		}
		tempDir = path.Join("/tmp", uniqueTempDir)
	} else {
		tempDir, err = ioutil.TempDir("", "derived_jwt")
		if err != nil {
			t.Fatal(err)
		}
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("Failed to connect to docker: %s", err)
	}

	dockerOptions := &dockertest.RunOptions{
		Repository: "vault",
		Tag:        "latest",
		Cmd: []string{"server", "-log-level=trace", "-dev", "-dev-three-node", fmt.Sprintf("-dev-root-token-id=%s", testToken),
			"-dev-listen-address=0.0.0.0:8200"},
		Env:    []string{"VAULT_DEV_TEMP_DIR=/tmp"},
		Mounts: []string{fmt.Sprintf("%s:/tmp", tempDir)},
	}
	resource, err := pool.RunWithOptions(dockerOptions)
	if err != nil {
		t.Fatalf("Could not start local Vault docker container: %s", err)
	}

	cleanup := func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Fatalf("error removing temp directory: %s", err)
		}

		if err := pool.Purge(resource); err != nil {
			t.Fatalf("Failed to cleanup local container: %s", err)
		}
	}

	retAddress := fmt.Sprintf("https://127.0.0.1:%s", resource.GetPort("8200/tcp"))
	tlsConfig := &api.TLSConfig{
		CACert:     path.Join(tempDir, "ca_cert.pem"),
		ClientCert: path.Join(tempDir, "node1_port_8200_cert.pem"),
		ClientKey:  path.Join(tempDir, "node1_port_8200_key.pem"),
	}

	// exponential backoff-retry
	var client *api.Client
	if err = pool.Retry(func() error {
		vaultConfig := api.DefaultConfig()
		vaultConfig.Address = retAddress
		if err := vaultConfig.ConfigureTLS(tlsConfig); err != nil {
			return err
		}
		client, err = api.NewClient(vaultConfig)
		if err != nil {
			return err
		}
		client.SetToken(testToken)

		// Unmount default kv mount to ensure availability
		if err := client.Sys().Unmount("kv"); err != nil {
			return err
		}

		return nil
	}); err != nil {
		cleanup()
		t.Fatalf("Could not connect to vault: %s", err)
	}
	return cleanup, client
}
