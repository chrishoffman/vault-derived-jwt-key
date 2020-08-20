package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"runtime"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/api"
	"github.com/ory/dockertest"
)

func prepareTestContainer() (func(), *api.Client) {
	testToken, err := uuid.GenerateUUID()
	if err != nil {
		log.Fatalf("err: %s", err)
	}
	log.Printf("generating test token: %s", testToken)

	var tempDir string
	// Docker for Mac does not play nice with TempDir
	if runtime.GOOS == "darwin" {
		uniqueTempDir, err := uuid.GenerateUUID()
		if err != nil {
			log.Fatalf("err: %s", err)
		}
		tempDir = path.Join("/tmp", uniqueTempDir)
	} else {
		tempDir, err = ioutil.TempDir("", "derived_jwt")
		if err != nil {
			log.Fatal(err)
		}
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		log.Fatalf("Failed to connect to docker: %s", err)
	}

	dockerOptions := &dockertest.RunOptions{
		Repository: "hashicorp/vault-enterprise",
		Tag:        "latest",
		Cmd: []string{"server", "-log-level=trace", "-dev", "-dev-three-node", fmt.Sprintf("-dev-root-token-id=%s", testToken),
			"-dev-listen-address=0.0.0.0:8200"},
		Env:    []string{"VAULT_DEV_TEMP_DIR=/tmp"},
		Mounts: []string{fmt.Sprintf("%s:/tmp", tempDir)},
	}
	resource, err := pool.RunWithOptions(dockerOptions)
	if err != nil {
		log.Fatalf("Could not start local Vault docker container: %s", err)
	}

	cleanup := func() {
		if err := os.RemoveAll(tempDir); err != nil {
			log.Fatalf("error removing temp directory: %s", err)
		}

		if err := pool.Purge(resource); err != nil {
			log.Fatalf("Failed to cleanup local container: %s", err)
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
		log.Fatalf("Could not connect to vault: %s", err)
	}
	return cleanup, client
}
