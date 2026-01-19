package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/sparkworx/terraform-provider-keychain/internal/datasources"
	"github.com/sparkworx/terraform-provider-keychain/internal/keychain"
	"github.com/sparkworx/terraform-provider-keychain/internal/resources"
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

	// Get keychain path from config or default to empty (uses default keychain)
	keychainPath := config.KeychainPath.ValueString()

	// Get password from config or environment variable
	password := config.Password.ValueString()
	if password == "" {
		password = os.Getenv("KEYCHAIN_PASSWORD")
	}

	// Open the keychain
	kc, err := keychain.Open(keychainPath)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to open keychain",
			"An error occurred while opening the keychain: "+err.Error(),
		)
		return
	}

	// Unlock the keychain if a password was provided
	if password != "" {
		err = kc.Unlock(password)
		if err != nil {
			resp.Diagnostics.AddError(
				"Unable to unlock keychain",
				"An error occurred while unlocking the keychain: "+err.Error(),
			)
			return
		}
	}

	// Make the keychain available to resources and data sources
	resp.DataSourceData = kc
	resp.ResourceData = kc
}

func (p *KeychainProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		resources.NewGenericPasswordResource,
		resources.NewInternetPasswordResource,
		resources.NewCertificateResource,
		resources.NewKeyResource,
	}
}

func (p *KeychainProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		datasources.NewGenericPasswordDataSource,
		datasources.NewInternetPasswordDataSource,
		datasources.NewCertificateDataSource,
		datasources.NewKeyDataSource,
	}
}
