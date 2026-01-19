package datasources

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/sparkworx/terraform-provider-keychain/internal/keychain"
)

var _ datasource.DataSource = &KeyDataSource{}

type KeyDataSource struct {
	keychain *keychain.Keychain
}

type KeyDataSourceModel struct {
	ID             types.String `tfsdk:"id"`
	Label          types.String `tfsdk:"label"`
	KeyData        types.String `tfsdk:"key_data"`
	KeyClass       types.String `tfsdk:"key_class"`
	KeyType        types.String `tfsdk:"key_type"`
	KeySizeInBits  types.Int64  `tfsdk:"key_size_bits"`
	Extractable    types.Bool   `tfsdk:"extractable"`
	ApplicationTag types.String `tfsdk:"application_tag"`
}

func NewKeyDataSource() datasource.DataSource {
	return &KeyDataSource{}
}

func (d *KeyDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_key"
}

func (d *KeyDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads a cryptographic key item from the macOS Keychain.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The unique identifier for this data source (the label).",
				Computed:    true,
			},
			"label": schema.StringAttribute{
				Description: "The label of the key to look up.",
				Required:    true,
			},
			"key_data": schema.StringAttribute{
				Description: "The key data (base64-encoded).",
				Computed:    true,
				Sensitive:   true,
			},
			"key_class": schema.StringAttribute{
				Description: "The class of the key: 'private', 'public', or 'symmetric'.",
				Computed:    true,
			},
			"key_type": schema.StringAttribute{
				Description: "The type of the key: 'rsa', 'ec', or 'aes'.",
				Computed:    true,
			},
			"key_size_bits": schema.Int64Attribute{
				Description: "The size of the key in bits.",
				Computed:    true,
			},
			"extractable": schema.BoolAttribute{
				Description: "Whether the key can be exported from the keychain.",
				Computed:    true,
			},
			"application_tag": schema.StringAttribute{
				Description: "An application-specific tag for the key.",
				Computed:    true,
			},
		},
	}
}

func (d *KeyDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

// keyClassFromKeychain converts keychain key class to user-friendly string
func keyClassFromKeychainDS(kc keychain.KeyClass) string {
	switch kc {
	case keychain.KeyClassPublic:
		return "public"
	case keychain.KeyClassPrivate:
		return "private"
	case keychain.KeyClassSymmetric:
		return "symmetric"
	default:
		return string(kc)
	}
}

// keyTypeFromKeychain converts keychain key type to user-friendly string
func keyTypeFromKeychainDS(kt keychain.KeyType) string {
	switch kt {
	case keychain.KeyTypeRSA:
		return "rsa"
	case keychain.KeyTypeEC:
		return "ec"
	case keychain.KeyTypeAES:
		return "aes"
	default:
		return string(kt)
	}
}

func (d *KeyDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data KeyDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	item, err := d.keychain.GetKey(data.Label.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading key",
			fmt.Sprintf("Could not read key with label=%q: %s",
				data.Label.ValueString(), err),
		)
		return
	}

	data.ID = types.StringValue(data.Label.ValueString())
	data.KeyData = types.StringValue(base64.StdEncoding.EncodeToString(item.KeyData))
	data.KeyClass = types.StringValue(keyClassFromKeychainDS(item.KeyClass))
	data.KeyType = types.StringValue(keyTypeFromKeychainDS(item.KeyType))
	data.KeySizeInBits = types.Int64Value(int64(item.KeySizeInBits))
	data.Extractable = types.BoolValue(item.Extractable)
	data.ApplicationTag = types.StringValue(item.ApplicationTag)

	// Zero out key data in memory
	for i := range item.KeyData {
		item.KeyData[i] = 0
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
