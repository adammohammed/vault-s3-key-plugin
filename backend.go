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
	store  map[string]S3Credential
}

type S3Credential struct {
	ID        int
	AccessKey string
	SecretKey string
}

func (c S3Credential) Format() map[string]interface{} {
	m := make(map[string]interface{})
	m["ID"] = c.ID
	m["access_key"] = c.AccessKey
	m["secret_key"] = c.SecretKey
	return m
}

func CreateLinodeClient(token string) linodego.Client {
	transportClient := &http.Client{
		Transport: &oauth2.Transport{
			Source: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}),
		},
	}

	return linodego.NewClient(transportClient)
}

func CreateS3Key(client linodego.Client, path string) (S3Credential, error) {
	opts := linodego.ObjectStorageKeyCreateOptions{
		Label: path,
	}

	key, err := client.CreateObjectStorageKey(context.TODO(), opts)

	if err != nil {
		return S3Credential{}, errwrap.Wrapf("key create failed: {{err}}", err)
	}

	return S3Credential{
		ID:        key.ID,
		AccessKey: key.AccessKey,
		SecretKey: key.SecretKey,
	}, nil
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &backend{
		store: make(map[string]S3Credential),
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
	credPath := fmt.Sprintf("%v/%v", req.ClientToken, path)
	keyData, exists := b.store[credPath]
	if !exists {
		var err error
		keyData, err := CreateS3Key(b.client, path)

		if err != nil {
			b.Logger().Warn("Could not create credential", "error", err)
		}
		b.store[credPath] = keyData

		go func() {
			lifetime := time.After(30 * time.Second)
			select {
			case <-lifetime:
				err := b.client.DeleteObjectStorageKey(context.TODO(), keyData.ID)
				delete(b.store, credPath)
				if err != nil {
					b.Logger().Warn("couldn't delete key", "KeyID", keyData.ID)
				}
			}
		}()
	}

	resp := &logical.Response{
		Data: keyData.Format(),
	}

	return resp, nil
}
