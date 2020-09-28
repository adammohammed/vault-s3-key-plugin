package s3key

import (
	"bufio"
	"context"
	"fmt"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/linode/linodego"
	"golang.org/x/oauth2"
	"net/http"
	"os"
	"time"
)

type backend struct {
	*framework.Backend
	client linodego.Client
	store  map[string][]byte
}

type S3Credential struct {
	ID        int
	AccessKey string
	SecretKey string
}

func CreateLinodeClient(token string) linodego.Client {
	transportClient := &http.Client{
		Transport: &oauth2.Transport{
			Source: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}),
		},
	}

	return linodego.NewClient(transportClient)
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {

	b := &backend{
		store: make(map[string][]byte),
	}

	b.Backend = &framework.Backend{
		Help:           "Test backend",
		BackendType:    logical.TypeLogical,
		InitializeFunc: b.initializer(),
	}

	b.Backend.Paths = append(b.Backend.Paths, b.paths()...)

	if conf == nil {
		return nil, fmt.Errorf("configuration passed into backend is nil")
	}

	b.Backend.Setup(ctx, conf)

	return b, nil
}

func (b *backend) initializer() framework.InitializeFunc {
	return func(context.Context, *logical.InitializationRequest) error {
		f, err := os.Open("linode-token")

		if err != nil {
			return fmt.Errorf("Couldn't open token file: %v\n", err)
		}

		scanner := bufio.NewScanner(f)
		var token string
		if scanner.Scan() {
			token = scanner.Text()
		}

		if token == "" {
			token = "default-token"
			b.Backend.Logger().Warn("using default-token")
		}
		b.Backend.Logger().Info("Creating Linode Client")
		b.client = CreateLinodeClient(token)
		return nil
	}
}

func (b *backend) paths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: framework.MatchAllRegex("path"),
			Fields: map[string]*framework.FieldSchema{
				"path": {
					Type:        framework.TypeString,
					Description: "Specifies the path of the secret.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleRead,

					Summary: "Read the secret.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleDelete,
					Summary:  "Deletes the secret.",
				},
			},

			ExistenceCheck: b.handleExistenceCheck,
		},
	}
}

func (b *backend) handleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)

	if err != nil {
		return false, errwrap.Wrapf("existence check failed: {{err}}", err)
	}

	return out != nil, nil
}

func (b *backend) handleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if req.ClientToken == "" {
		return nil, fmt.Errorf("client token empty")
	}

	path := data.Get("path").(string)
	opts := linodego.ObjectStorageKeyCreateOptions{
		Label: path,
	}

	key, err := b.client.CreateObjectStorageKey(context.TODO(), opts)

	if err != nil {
		return nil, errwrap.Wrapf("key create failed: {{err}}", err)
	}

	keyData := S3Credential{
		ID:        key.ID,
		AccessKey: key.AccessKey,
		SecretKey: key.SecretKey,
	}

	keys := make(map[string]interface{}, 3)
	keys["ID"] = keyData.ID
	keys["AccessKey"] = keyData.AccessKey
	keys["SecretKey"] = keyData.SecretKey

	go func() {
		lifetime := time.After(30 * time.Second)
		select {

		case <-lifetime:
			err := b.client.DeleteObjectStorageKey(context.TODO(), keyData.ID)
			if err != nil {
				b.Logger().Warn("Couldn't delete key [%v]", keyData.ID)
			}
		}
	}()

	// Generate the response
	resp := &logical.Response{
		Data: keys,
	}

	return resp, nil
}

func (b *backend) handleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if req.ClientToken == "" {
		return nil, fmt.Errorf("client token empty")
	}

	path := data.Get("path").(string)

	delete(b.store, req.ClientToken+"/"+path)

	return nil, nil
}
