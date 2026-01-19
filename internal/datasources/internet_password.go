package datasources

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/sparkworx/terraform-provider-keychain/internal/keychain"
)

var _ datasource.DataSource = &InternetPasswordDataSource{}

type InternetPasswordDataSource struct {
	keychain *keychain.Keychain
}

type InternetPasswordDataSourceModel struct {
	ID                 types.String `tfsdk:"id"`
	Server             types.String `tfsdk:"server"`
	Account            types.String `tfsdk:"account"`
	Password           types.String `tfsdk:"password"`
	Protocol           types.String `tfsdk:"protocol"`
	Port               types.Int64  `tfsdk:"port"`
	Path               types.String `tfsdk:"path"`
	AuthenticationType types.String `tfsdk:"authentication_type"`
	SecurityDomain     types.String `tfsdk:"security_domain"`
	Label              types.String `tfsdk:"label"`
}

// Protocol mapping: user-friendly names to keychain internal codes
var protocolToKeychainMap = map[string]keychain.Protocol{
	"http":  keychain.ProtocolHTTP,
	"https": keychain.ProtocolHTTPS,
	"ftp":   keychain.ProtocolFTP,
	"ssh":   keychain.ProtocolSSH,
	"smb":   keychain.ProtocolSMB,
	"afp":   keychain.ProtocolAFP,
	"ldap":  keychain.ProtocolLDAP,
	"ldaps": keychain.ProtocolLDAPS,
}

var authTypeFromKeychainMap = map[keychain.AuthenticationType]string{
	keychain.AuthTypeHTTPBasic:  "httpBasic",
	keychain.AuthTypeHTTPDigest: "httpDigest",
	keychain.AuthTypeHTMLForm:   "htmlForm",
	keychain.AuthTypeDefault:    "default",
}

func protocolToKeychain(s string) keychain.Protocol {
	if p, ok := protocolToKeychainMap[s]; ok {
		return p
	}
	return keychain.Protocol(s)
}

func authTypeFromKeychain(a keychain.AuthenticationType) string {
	if s, ok := authTypeFromKeychainMap[a]; ok {
		return s
	}
	return string(a)
}

func NewInternetPasswordDataSource() datasource.DataSource {
	return &InternetPasswordDataSource{}
}

func (d *InternetPasswordDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_internet_password"
}

func (d *InternetPasswordDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads an internet password item from the macOS Keychain.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The unique identifier for this data source (server:account:protocol:port).",
				Computed:    true,
			},
			"server": schema.StringAttribute{
				Description: "The server hostname (kSecAttrServer).",
				Required:    true,
			},
			"account": schema.StringAttribute{
				Description: "The account name/username (kSecAttrAccount).",
				Required:    true,
			},
			"protocol": schema.StringAttribute{
				Description: "The protocol (http, https, ftp, ssh, smb, afp, ldap, ldaps).",
				Required:    true,
				Validators: []validator.String{
					stringvalidator.OneOf("http", "https", "ftp", "ssh", "smb", "afp", "ldap", "ldaps"),
				},
			},
			"port": schema.Int64Attribute{
				Description: "The port number. Use 0 for any port.",
				Required:    true,
			},
			"password": schema.StringAttribute{
				Description: "The password data.",
				Computed:    true,
				Sensitive:   true,
			},
			"path": schema.StringAttribute{
				Description: "The URL path.",
				Computed:    true,
			},
			"authentication_type": schema.StringAttribute{
				Description: "The authentication type (httpBasic, httpDigest, htmlForm, default).",
				Computed:    true,
			},
			"security_domain": schema.StringAttribute{
				Description: "The security domain.",
				Computed:    true,
			},
			"label": schema.StringAttribute{
				Description: "The human-readable label for the item.",
				Computed:    true,
			},
		},
	}
}

func (d *InternetPasswordDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	kc, ok := req.ProviderData.(*keychain.Keychain)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *keychain.Keychain, got: %T", req.ProviderData),
		)
		return
	}

	d.keychain = kc
}

func (d *InternetPasswordDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data InternetPasswordDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	item, err := d.keychain.GetInternetPassword(
		data.Server.ValueString(),
		data.Account.ValueString(),
		protocolToKeychain(data.Protocol.ValueString()),
		int(data.Port.ValueInt64()),
	)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading internet password",
			fmt.Sprintf("Could not read internet password for server=%q account=%q protocol=%q port=%d: %s",
				data.Server.ValueString(), data.Account.ValueString(),
				data.Protocol.ValueString(), data.Port.ValueInt64(), err),
		)
		return
	}

	data.ID = types.StringValue(fmt.Sprintf("%s:%s:%s:%d",
		data.Server.ValueString(),
		data.Account.ValueString(),
		data.Protocol.ValueString(),
		data.Port.ValueInt64(),
	))
	data.Password = types.StringValue(string(item.Password))
	data.Path = types.StringValue(item.Path)
	data.AuthenticationType = types.StringValue(authTypeFromKeychain(item.AuthenticationType))
	data.SecurityDomain = types.StringValue(item.SecurityDomain)
	data.Label = types.StringValue(item.Label)

	// Zero out the password in memory
	for i := range item.Password {
		item.Password[i] = 0
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
