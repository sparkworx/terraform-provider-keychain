package datasources

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/sparkworx/terraform-provider-keychain/internal/keychain"
)

var _ datasource.DataSource = &GenericPasswordDataSource{}

type GenericPasswordDataSource struct {
	keychain *keychain.Keychain
}

type GenericPasswordDataSourceModel struct {
	Service     types.String `tfsdk:"service"`
	Account     types.String `tfsdk:"account"`
	Password    types.String `tfsdk:"password"`
	Label       types.String `tfsdk:"label"`
	Description types.String `tfsdk:"description"`
	ID          types.String `tfsdk:"id"`
}

func NewGenericPasswordDataSource() datasource.DataSource {
	return &GenericPasswordDataSource{}
}

func (d *GenericPasswordDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_generic_password"
}

func (d *GenericPasswordDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads a generic password item from the macOS Keychain.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The unique identifier for this data source (service:account).",
				Computed:    true,
			},
			"service": schema.StringAttribute{
				Description: "The service name for the password item (kSecAttrService).",
				Required:    true,
			},
			"account": schema.StringAttribute{
				Description: "The account name for the password item (kSecAttrAccount).",
				Required:    true,
			},
			"password": schema.StringAttribute{
				Description: "The password data.",
				Computed:    true,
				Sensitive:   true,
			},
			"label": schema.StringAttribute{
				Description: "The human-readable label for the item.",
				Computed:    true,
			},
			"description": schema.StringAttribute{
				Description: "The description of the item.",
				Computed:    true,
			},
		},
	}
}

func (d *GenericPasswordDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *GenericPasswordDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data GenericPasswordDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	item, err := d.keychain.GetGenericPassword(data.Service.ValueString(), data.Account.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading generic password",
			fmt.Sprintf("Could not read generic password for service=%q account=%q: %s",
				data.Service.ValueString(), data.Account.ValueString(), err),
		)
		return
	}

	data.ID = types.StringValue(fmt.Sprintf("%s:%s", data.Service.ValueString(), data.Account.ValueString()))
	data.Password = types.StringValue(string(item.Password))
	data.Label = types.StringValue(item.Label)
	data.Description = types.StringValue(item.Description)

	// Zero out the password in memory
	for i := range item.Password {
		item.Password[i] = 0
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
