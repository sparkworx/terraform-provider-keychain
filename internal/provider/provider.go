package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ provider.Provider = &KeychainProvider{}

type KeychainProvider struct {
	version string
}

type KeychainProviderModel struct {
	KeychainPath types.String `tfsdk:"keychain_path"`
	Password     types.String `tfsdk:"password"`
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &KeychainProvider{
			version: version,
		}
	}
}

func (p *KeychainProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "keychain"
	resp.Version = p.version
}

func (p *KeychainProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manage items in macOS Keychains.",
		Attributes: map[string]schema.Attribute{
			"keychain_path": schema.StringAttribute{
				Description: "Full path to keychain file. Defaults to default keychain.",
				Optional:    true,
			},
			"password": schema.StringAttribute{
				Description: "Password to unlock keychain. Can use KEYCHAIN_PASSWORD env var.",
				Optional:    true,
				Sensitive:   true,
			},
		},
	}
}

func (p *KeychainProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config KeychainProviderModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// TODO: Initialize keychain client and pass to resources/datasources
}

func (p *KeychainProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		// TODO: Add resources
	}
}

func (p *KeychainProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		// TODO: Add datasources
	}
}
