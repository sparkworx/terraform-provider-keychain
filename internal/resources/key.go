package resources

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/sparkworx/terraform-provider-keychain/internal/keychain"
)

var (
	_ resource.Resource                = &KeyResource{}
	_ resource.ResourceWithImportState = &KeyResource{}
)

type KeyResource struct {
	keychain *keychain.Keychain
}

type KeyResourceModel struct {
	ID             types.String `tfsdk:"id"`
	Label          types.String `tfsdk:"label"`
	KeyData        types.String `tfsdk:"key_data"`
	KeyClass       types.String `tfsdk:"key_class"`
	KeyType        types.String `tfsdk:"key_type"`
	KeySizeInBits  types.Int64  `tfsdk:"key_size_bits"`
	Extractable    types.Bool   `tfsdk:"extractable"`
	Permanent      types.Bool   `tfsdk:"permanent"`
	ApplicationTag types.String `tfsdk:"application_tag"`
}

func NewKeyResource() resource.Resource {
	return &KeyResource{}
}

func (r *KeyResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_key"
}

func (r *KeyResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a cryptographic key item in the macOS Keychain.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The unique identifier for this resource (the label).",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"label": schema.StringAttribute{
				Description: "A human-readable label for the key. This is the unique identifier.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"key_data": schema.StringAttribute{
				Description: "The key data (base64 encoded for binary keys, or raw for text-based keys like PEM).",
				Required:    true,
				Sensitive:   true,
			},
			"key_class": schema.StringAttribute{
				Description: "The class of the key: 'private', 'public', or 'symmetric'.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.OneOf("private", "public", "symmetric"),
				},
			},
			"key_type": schema.StringAttribute{
				Description: "The type of the key: 'rsa', 'ec', or 'aes'.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.OneOf("rsa", "ec", "aes"),
				},
			},
			"key_size_bits": schema.Int64Attribute{
				Description: "The size of the key in bits (e.g., 256 for AES-256, 2048 for RSA-2048).",
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(0),
				PlanModifiers: []planmodifier.Int64{
					// key size is typically immutable
				},
			},
			"extractable": schema.BoolAttribute{
				Description: "Whether the key can be exported from the keychain.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
			},
			"permanent": schema.BoolAttribute{
				Description: "Whether the key is stored permanently in the keychain.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
			},
			"application_tag": schema.StringAttribute{
				Description: "An application-specific tag for the key.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *KeyResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

// parseKeyData parses key data from the config (either base64 or raw)
func parseKeyData(keyDataStr string) ([]byte, error) {
	// Try base64 decode first
	decoded, err := base64.StdEncoding.DecodeString(keyDataStr)
	if err == nil {
		return decoded, nil
	}
	// If base64 fails, treat as raw bytes
	return []byte(keyDataStr), nil
}

// keyClassToKeychain converts user-friendly key class to keychain type
func keyClassToKeychain(keyClass string) keychain.KeyClass {
	switch keyClass {
	case "public":
		return keychain.KeyClassPublic
	case "private":
		return keychain.KeyClassPrivate
	case "symmetric":
		return keychain.KeyClassSymmetric
	default:
		return keychain.KeyClass(keyClass)
	}
}

// keyClassFromKeychain converts keychain key class to user-friendly string
func keyClassFromKeychain(kc keychain.KeyClass) string {
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

// keyTypeToKeychain converts user-friendly key type to keychain type
func keyTypeToKeychain(keyType string) keychain.KeyType {
	switch keyType {
	case "rsa":
		return keychain.KeyTypeRSA
	case "ec":
		return keychain.KeyTypeEC
	case "aes":
		return keychain.KeyTypeAES
	default:
		return keychain.KeyType(keyType)
	}
}

// keyTypeFromKeychain converts keychain key type to user-friendly string
func keyTypeFromKeychain(kt keychain.KeyType) string {
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

func (r *KeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data KeyResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	keyBytes, err := parseKeyData(data.KeyData.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error parsing key data",
			fmt.Sprintf("Could not parse key data: %s", err),
		)
		return
	}

	item := &keychain.KeyItem{
		Label:          data.Label.ValueString(),
		KeyData:        keyBytes,
		KeyClass:       keyClassToKeychain(data.KeyClass.ValueString()),
		KeyType:        keyTypeToKeychain(data.KeyType.ValueString()),
		KeySizeInBits:  int(data.KeySizeInBits.ValueInt64()),
		Extractable:    data.Extractable.ValueBool(),
		Permanent:      data.Permanent.ValueBool(),
		ApplicationTag: data.ApplicationTag.ValueString(),
	}

	err = r.keychain.AddKey(item)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating key",
			fmt.Sprintf("Could not create key: %s", err),
		)
		return
	}

	data.ID = types.StringValue(data.Label.ValueString())

	// Ensure application_tag is set (could be empty string)
	if data.ApplicationTag.IsUnknown() {
		data.ApplicationTag = types.StringValue("")
	}

	// Keep original key_data value from config to avoid spurious diffs

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *KeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data KeyResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	item, err := r.keychain.GetKey(data.Label.ValueString())
	if err != nil {
		if keychain.IsItemNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError(
			"Error reading key",
			fmt.Sprintf("Could not read key: %s", err),
		)
		return
	}

	// Check if the key data matches the state to avoid spurious diffs
	if !data.KeyData.IsNull() && !data.KeyData.IsUnknown() {
		stateKeyBytes, _ := parseKeyData(data.KeyData.ValueString())
		keychainB64 := base64.StdEncoding.EncodeToString(item.KeyData)
		stateB64 := base64.StdEncoding.EncodeToString(stateKeyBytes)
		if keychainB64 != stateB64 {
			// Key has changed externally, update state
			data.KeyData = types.StringValue(keychainB64)
		}
		// else: keys match, keep original state value
	} else {
		// No prior state, use base64-encoded value
		data.KeyData = types.StringValue(base64.StdEncoding.EncodeToString(item.KeyData))
	}

	data.KeyClass = types.StringValue(keyClassFromKeychain(item.KeyClass))
	data.KeyType = types.StringValue(keyTypeFromKeychain(item.KeyType))
	data.KeySizeInBits = types.Int64Value(int64(item.KeySizeInBits))
	data.Extractable = types.BoolValue(item.Extractable)

	// Zero out key data in memory
	for i := range item.KeyData {
		item.KeyData[i] = 0
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *KeyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data KeyResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	keyBytes, err := parseKeyData(data.KeyData.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error parsing key data",
			fmt.Sprintf("Could not parse key data: %s", err),
		)
		return
	}

	// Delete existing and re-add (keychain doesn't have key update)
	_ = r.keychain.DeleteKey(data.Label.ValueString())

	item := &keychain.KeyItem{
		Label:          data.Label.ValueString(),
		KeyData:        keyBytes,
		KeyClass:       keyClassToKeychain(data.KeyClass.ValueString()),
		KeyType:        keyTypeToKeychain(data.KeyType.ValueString()),
		KeySizeInBits:  int(data.KeySizeInBits.ValueInt64()),
		Extractable:    data.Extractable.ValueBool(),
		Permanent:      data.Permanent.ValueBool(),
		ApplicationTag: data.ApplicationTag.ValueString(),
	}

	err = r.keychain.AddKey(item)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating key",
			fmt.Sprintf("Could not update key: %s", err),
		)
		return
	}

	// Keep original key_data value from config

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *KeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data KeyResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.keychain.DeleteKey(data.Label.ValueString())
	if err != nil {
		if keychain.IsItemNotFound(err) {
			return
		}
		resp.Diagnostics.AddError(
			"Error deleting key",
			fmt.Sprintf("Could not delete key: %s", err),
		)
		return
	}
}

func (r *KeyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// ID is the label
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("label"), req.ID)...)
}
