package resources

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/sparkworx/terraform-provider-keychain/internal/keychain"
)

var (
	_ resource.Resource                = &GenericPasswordResource{}
	_ resource.ResourceWithImportState = &GenericPasswordResource{}
)

type GenericPasswordResource struct {
	keychain *keychain.Keychain
}

type GenericPasswordResourceModel struct {
	Service     types.String `tfsdk:"service"`
	Account     types.String `tfsdk:"account"`
	Password    types.String `tfsdk:"password"`
	Label       types.String `tfsdk:"label"`
	Description types.String `tfsdk:"description"`
	AccessGroup types.String `tfsdk:"access_group"`
	ID          types.String `tfsdk:"id"`
}

func NewGenericPasswordResource() resource.Resource {
	return &GenericPasswordResource{}
}

func (r *GenericPasswordResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_generic_password"
}

func (r *GenericPasswordResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a generic password item in the macOS Keychain.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The unique identifier for this resource (service:account).",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"service": schema.StringAttribute{
				Description: "The service name for the password item (kSecAttrService).",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"account": schema.StringAttribute{
				Description: "The account name for the password item (kSecAttrAccount).",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"password": schema.StringAttribute{
				Description: "The password data.",
				Required:    true,
				Sensitive:   true,
			},
			"label": schema.StringAttribute{
				Description: "A human-readable label for the item. If not set, macOS will use the service name.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"description": schema.StringAttribute{
				Description: "A description of the item.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"access_group": schema.StringAttribute{
				Description: "The keychain access group.",
				Optional:    true,
			},
		},
	}
}

func (r *GenericPasswordResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	kc, ok := req.ProviderData.(*keychain.Keychain)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *keychain.Keychain, got: %T", req.ProviderData),
		)
		return
	}

	r.keychain = kc
}

func (r *GenericPasswordResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data GenericPasswordResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	item := &keychain.GenericPasswordItem{
		Service:     data.Service.ValueString(),
		Account:     data.Account.ValueString(),
		Password:    []byte(data.Password.ValueString()),
		Label:       data.Label.ValueString(),
		Description: data.Description.ValueString(),
		AccessGroup: data.AccessGroup.ValueString(),
	}

	err := r.keychain.AddGenericPassword(item)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating generic password",
			fmt.Sprintf("Could not create generic password: %s", err),
		)
		return
	}

	data.ID = types.StringValue(fmt.Sprintf("%s:%s", data.Service.ValueString(), data.Account.ValueString()))

	// Read back the item to get any computed values (like label which macOS may auto-populate)
	created, err := r.keychain.GetGenericPassword(data.Service.ValueString(), data.Account.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading created generic password",
			fmt.Sprintf("Could not read back created generic password: %s", err),
		)
		return
	}

	// Set computed values from what's actually in the keychain
	data.Label = types.StringValue(created.Label)
	data.Description = types.StringValue(created.Description)

	// Zero out the password in memory
	for i := range created.Password {
		created.Password[i] = 0
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *GenericPasswordResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data GenericPasswordResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	item, err := r.keychain.GetGenericPassword(data.Service.ValueString(), data.Account.ValueString())
	if err != nil {
		if keychain.IsItemNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError(
			"Error reading generic password",
			fmt.Sprintf("Could not read generic password: %s", err),
		)
		return
	}

	data.Password = types.StringValue(string(item.Password))
	data.Label = types.StringValue(item.Label)
	data.Description = types.StringValue(item.Description)

	// Zero out the password in memory
	for i := range item.Password {
		item.Password[i] = 0
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *GenericPasswordResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data GenericPasswordResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	item := &keychain.GenericPasswordItem{
		Service:     data.Service.ValueString(),
		Account:     data.Account.ValueString(),
		Password:    []byte(data.Password.ValueString()),
		Label:       data.Label.ValueString(),
		Description: data.Description.ValueString(),
		AccessGroup: data.AccessGroup.ValueString(),
	}

	err := r.keychain.UpdateGenericPassword(item)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating generic password",
			fmt.Sprintf("Could not update generic password: %s", err),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *GenericPasswordResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data GenericPasswordResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.keychain.DeleteGenericPassword(data.Service.ValueString(), data.Account.ValueString())
	if err != nil {
		if keychain.IsItemNotFound(err) {
			return
		}
		resp.Diagnostics.AddError(
			"Error deleting generic password",
			fmt.Sprintf("Could not delete generic password: %s", err),
		)
		return
	}
}

func (r *GenericPasswordResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// ID format is "service:account"
	id := req.ID
	parts := strings.SplitN(id, ":", 2)
	if len(parts) != 2 {
		resp.Diagnostics.AddError(
			"Invalid import ID",
			fmt.Sprintf("Expected import ID in format 'service:account', got: %s", id),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("service"), parts[0])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("account"), parts[1])...)
}
