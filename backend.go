package s3key

import (
	"context"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/logical"
)

type backend struct {
	*framework.Backend
	store map[string][]byte
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &backend {

	}

	b.Backend = &framework.Backend{
		Help: "Test backend",
		BackendType: logical.TypeLogical,
	}

	b.Backend.Paths = append(b.Backend.Paths, paths()...)

	if conf == nil {
		return nil, fmt.Errorf("configuration passed into backend is nil")
	}

	b.Backend.Setup(ctx, conf)


	return b, nil
}

func (b *backend) paths() []*framework.Path {
	return []*framework.Path {
		{
			Pattern: framework.MatchAllRegex("path"),
			Fields: map[string]*framework.FieldSchema{
				Type: logical.TypeString,
				Description: "Specifies the path of the secret.",
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleRead,
					Summary: "Read the secret.",
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.handleCreate,
					Summary: "Create secrets.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleDelete,
					Summary: "Deletes the secret.",
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

	// Decode the data
	var rawData map[string]interface{}
	if err := jsonutil.DecodeJSON(b.store[req.ClientToken+"/"+path], &rawData); err != nil {
		return nil, errwrap.Wrapf("json decoding failed: {{err}}", err)
	}

	// Generate the response
	resp := &logical.Response{
		Data: rawData,
	}

	return resp, nil
}


func (b *backend) handleCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if req.ClientToken == "" {
		return nil, fmt.Errorf("client token empty")
	}

	if len(req.Data) == 0 {
		return nil, fmt.Errorf("data must be provide to store in secret")
	}

	path := data.Get("path").(string)

	buf, err := json.Marshal(req.Data)
	if err != nil {
		return nil, errwrap.Wrapf("json encoding failed: {{err}}", err)
	}

	b.store[req.ClientToken+"/"+path] = buf

	return nil, nil
}

func (b *backend) handleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logicalResponse, error) {
	if req.ClientToken == "" {
		return nil, fmt.Errorf("client token empty")
	}

	path := data.Get("path").(string)

	delete(b.store, path)

	return nil, nil
}
