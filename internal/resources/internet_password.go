package resources

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/sparkworx/terraform-provider-keychain/internal/keychain"
)

var (
	_ resource.Resource                = &InternetPasswordResource{}
	_ resource.ResourceWithImportState = &InternetPasswordResource{}
)

type InternetPasswordResource struct {
	keychain *keychain.Keychain
}

type InternetPasswordResourceModel struct {
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

var protocolFromKeychainMap = map[keychain.Protocol]string{
	keychain.ProtocolHTTP:  "http",
	keychain.ProtocolHTTPS: "https",
	keychain.ProtocolFTP:   "ftp",
	keychain.ProtocolSSH:   "ssh",
	keychain.ProtocolSMB:   "smb",
	keychain.ProtocolAFP:   "afp",
	keychain.ProtocolLDAP:  "ldap",
	keychain.ProtocolLDAPS: "ldaps",
}

// AuthType mapping: user-friendly names to keychain internal codes
var authTypeToKeychainMap = map[string]keychain.AuthenticationType{
	"httpBasic":  keychain.AuthTypeHTTPBasic,
	"httpDigest": keychain.AuthTypeHTTPDigest,
	"htmlForm":   keychain.AuthTypeHTMLForm,
	"default":    keychain.AuthTypeDefault,
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

func protocolFromKeychain(p keychain.Protocol) string {
	if s, ok := protocolFromKeychainMap[p]; ok {
		return s
	}
	return string(p)
}

func authTypeToKeychain(s string) keychain.AuthenticationType {
	if a, ok := authTypeToKeychainMap[s]; ok {
		return a
	}
	return keychain.AuthenticationType(s)
}

func authTypeFromKeychain(a keychain.AuthenticationType) string {
	if s, ok := authTypeFromKeychainMap[a]; ok {
		return s
	}
	return string(a)
}

func buildInternetPasswordID(server, account, protocol string, port int64) string {
	return fmt.Sprintf("%s:%s:%s:%d", server, account, protocol, port)
}

func parseInternetPasswordID(id string) (server, account, protocol string, port int64, err error) {
	parts := strings.Split(id, ":")
	if len(parts) != 4 {
		err = fmt.Errorf("expected import ID in format 'server:account:protocol:port', got: %s", id)
		return
	}
	server = parts[0]
	account = parts[1]
	protocol = parts[2]
	port, err = strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		err = fmt.Errorf("invalid port number in import ID: %s", parts[3])
		return
	}
	return
}

func NewInternetPasswordResource() resource.Resource {
	return &InternetPasswordResource{}
}

func (r *InternetPasswordResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_internet_password"
}

func (r *InternetPasswordResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an internet password item in the macOS Keychain.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The unique identifier for this resource (server:account:protocol:port).",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"server": schema.StringAttribute{
				Description: "The server hostname (kSecAttrServer).",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"account": schema.StringAttribute{
				Description: "The account name/username (kSecAttrAccount).",
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
			"protocol": schema.StringAttribute{
				Description: "The protocol (http, https, ftp, ssh, smb, afp, ldap, ldaps).",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.OneOf("http", "https", "ftp", "ssh", "smb", "afp", "ldap", "ldaps"),
				},
			},
			"port": schema.Int64Attribute{
				Description: "The port number. Defaults to 0 (any port).",
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(0),
			},
			"path": schema.StringAttribute{
				Description: "The URL path.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"authentication_type": schema.StringAttribute{
				Description: "The authentication type (httpBasic, httpDigest, htmlForm, default).",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Validators: []validator.String{
					stringvalidator.OneOf("httpBasic", "httpDigest", "htmlForm", "default"),
				},
			},
			"security_domain": schema.StringAttribute{
				Description: "The security domain.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"label": schema.StringAttribute{
				Description: "A human-readable label for the item.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *InternetPasswordResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *InternetPasswordResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data InternetPasswordResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	item := &keychain.InternetPasswordItem{
		Server:             data.Server.ValueString(),
		Account:            data.Account.ValueString(),
		Password:           []byte(data.Password.ValueString()),
		Protocol:           protocolToKeychain(data.Protocol.ValueString()),
		Port:               int(data.Port.ValueInt64()),
		Path:               data.Path.ValueString(),
		AuthenticationType: authTypeToKeychain(data.AuthenticationType.ValueString()),
		SecurityDomain:     data.SecurityDomain.ValueString(),
		Label:              data.Label.ValueString(),
	}

	err := r.keychain.AddInternetPassword(item)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating internet password",
			fmt.Sprintf("Could not create internet password: %s", err),
		)
		return
	}

	data.ID = types.StringValue(buildInternetPasswordID(
		data.Server.ValueString(),
		data.Account.ValueString(),
		data.Protocol.ValueString(),
		data.Port.ValueInt64(),
	))

	// Read back the item to get any computed values
	created, err := r.keychain.GetInternetPassword(
		data.Server.ValueString(),
		data.Account.ValueString(),
		protocolToKeychain(data.Protocol.ValueString()),
		int(data.Port.ValueInt64()),
	)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading created internet password",
			fmt.Sprintf("Could not read back created internet password: %s", err),
		)
		return
	}

	// Set computed values from what's actually in the keychain
	data.Path = types.StringValue(created.Path)
	data.AuthenticationType = types.StringValue(authTypeFromKeychain(created.AuthenticationType))
	data.SecurityDomain = types.StringValue(created.SecurityDomain)
	data.Label = types.StringValue(created.Label)

	// Zero out the password in memory
	for i := range created.Password {
		created.Password[i] = 0
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *InternetPasswordResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data InternetPasswordResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	item, err := r.keychain.GetInternetPassword(
		data.Server.ValueString(),
		data.Account.ValueString(),
		protocolToKeychain(data.Protocol.ValueString()),
		int(data.Port.ValueInt64()),
	)
	if err != nil {
		if keychain.IsItemNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError(
			"Error reading internet password",
			fmt.Sprintf("Could not read internet password: %s", err),
		)
		return
	}

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

func (r *InternetPasswordResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data InternetPasswordResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	item := &keychain.InternetPasswordItem{
		Server:             data.Server.ValueString(),
		Account:            data.Account.ValueString(),
		Password:           []byte(data.Password.ValueString()),
		Protocol:           protocolToKeychain(data.Protocol.ValueString()),
		Port:               int(data.Port.ValueInt64()),
		Path:               data.Path.ValueString(),
		AuthenticationType: authTypeToKeychain(data.AuthenticationType.ValueString()),
		SecurityDomain:     data.SecurityDomain.ValueString(),
		Label:              data.Label.ValueString(),
	}

	err := r.keychain.UpdateInternetPassword(item)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating internet password",
			fmt.Sprintf("Could not update internet password: %s", err),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *InternetPasswordResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data InternetPasswordResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.keychain.DeleteInternetPassword(
		data.Server.ValueString(),
		data.Account.ValueString(),
		protocolToKeychain(data.Protocol.ValueString()),
		int(data.Port.ValueInt64()),
	)
	if err != nil {
		if keychain.IsItemNotFound(err) {
			return
		}
		resp.Diagnostics.AddError(
			"Error deleting internet password",
			fmt.Sprintf("Could not delete internet password: %s", err),
		)
		return
	}
}

func (r *InternetPasswordResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	server, account, protocol, port, err := parseInternetPasswordID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid import ID",
			err.Error(),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("server"), server)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("account"), account)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("protocol"), protocol)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("port"), port)...)
}
