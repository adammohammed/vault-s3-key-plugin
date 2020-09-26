package main

import (
    "os"

    s3key "github.com/adammohammed/s3-key-plugin"
    "github.com/hashicorp/vault/api"
    "github.com/hashicorp/vault/sdk/plugin"
)

func main() {
    apiClientMeta := &api.PluginAPIClientMeta{}
    flags := apiClientMeta.FlagSet()
    flags.Parse(os.Args[1:])

    tlsConfig := apiClientMeta.GetTLSConfig()
    tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

    err := plugin.Serve(&plugin.ServeOpts{
        BackendFactoryFunc: s3key.Factory,
        TLSProviderFunc:    tlsProviderFunc,
    })
    if err != nil {
        logger := hclog.New(&hclog.LoggerOptions{})

        logger.Error("plugin shutting down", "error", err)
        os.Exit(1)
    }
}
