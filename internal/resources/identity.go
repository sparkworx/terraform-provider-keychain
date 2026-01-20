package resources

import (
	"context"
	"crypto/sha1" // #nosec G505 -- SHA1 used for standard certificate fingerprinting, not security
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/sparkworx/terraform-provider-keychain/internal/keychain"
)

var (
	_ resource.Resource                = &IdentityResource{}
	_ resource.ResourceWithImportState = &IdentityResource{}
)

type IdentityResource struct {
	keychain *keychain.Keychain
}

type IdentityResourceModel struct {
	ID                types.String `tfsdk:"id"`
	Label             types.String `tfsdk:"label"`
	PKCS12Data        types.String `tfsdk:"pkcs12_data"`
	Password          types.String `tfsdk:"password"`
	Subject           types.String `tfsdk:"subject"`
	Issuer            types.String `tfsdk:"issuer"`
	SerialNumber      types.String `tfsdk:"serial_number"`
	NotBefore         types.String `tfsdk:"not_before"`
	NotAfter          types.String `tfsdk:"not_after"`
	FingerprintSHA1   types.String `tfsdk:"fingerprint_sha1"`
	FingerprintSHA256 types.String `tfsdk:"fingerprint_sha256"`
	KeyType           types.String `tfsdk:"key_type"`
	KeySizeInBits     types.Int64  `tfsdk:"key_size_bits"`
}

func NewIdentityResource() resource.Resource {
	return &IdentityResource{}
}

func (r *IdentityResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_identity"
}

func (r *IdentityResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an identity (certificate + private key) item in the macOS Keychain.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The unique identifier for this resource (the label).",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"label": schema.StringAttribute{
				Description: "A human-readable label for the identity. This is the unique identifier.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"pkcs12_data": schema.StringAttribute{
				Description: "The PKCS#12 bundle (base64 encoded) containing the certificate and private key.",
				Required:    true,
				Sensitive:   true,
			},
			"password": schema.StringAttribute{
				Description: "The password for the PKCS#12 bundle.",
				Required:    true,
				Sensitive:   true,
			},
			"subject": schema.StringAttribute{
				Description: "The certificate subject.",
				Computed:    true,
			},
			"issuer": schema.StringAttribute{
				Description: "The certificate issuer.",
				Computed:    true,
			},
			"serial_number": schema.StringAttribute{
				Description: "The certificate serial number.",
				Computed:    true,
			},
			"not_before": schema.StringAttribute{
				Description: "The certificate validity start time (RFC3339 format).",
				Computed:    true,
			},
			"not_after": schema.StringAttribute{
				Description: "The certificate validity end time (RFC3339 format).",
				Computed:    true,
			},
			"fingerprint_sha1": schema.StringAttribute{
				Description: "The SHA1 fingerprint of the certificate.",
				Computed:    true,
			},
			"fingerprint_sha256": schema.StringAttribute{
				Description: "The SHA256 fingerprint of the certificate.",
				Computed:    true,
			},
			"key_type": schema.StringAttribute{
				Description: "The type of the private key: 'rsa' or 'ec'.",
				Computed:    true,
			},
			"key_size_bits": schema.Int64Attribute{
				Description: "The size of the private key in bits.",
				Computed:    true,
			},
		},
	}
}

func (r *IdentityResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

// parsePKCS12 parses base64-encoded PKCS#12 data and returns the raw bytes
func parsePKCS12(pkcs12DataStr string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(pkcs12DataStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 PKCS#12 data: %w", err)
	}
	return decoded, nil
}

// computeIdentityFingerprints computes SHA1 and SHA256 fingerprints of certificate DER data
func computeIdentityFingerprints(certDER []byte) (sha1Hex, sha256Hex string) {
	sha1Sum := sha1.Sum(certDER) // #nosec G401 -- SHA1 used for standard certificate fingerprinting
	sha256Sum := sha256.Sum256(certDER)
	return hex.EncodeToString(sha1Sum[:]), hex.EncodeToString(sha256Sum[:])
}

// populateIdentityComputedFields fills in the computed identity attributes from certificate data
func populateIdentityComputedFields(data *IdentityResourceModel, item *keychain.IdentityItem) error {
	// Parse the certificate to get subject/issuer/dates
	cert, err := x509.ParseCertificate(item.CertificateData)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	data.Subject = types.StringValue(cert.Subject.String())
	data.Issuer = types.StringValue(cert.Issuer.String())
	data.SerialNumber = types.StringValue(cert.SerialNumber.String())
	data.NotBefore = types.StringValue(cert.NotBefore.UTC().Format("2006-01-02T15:04:05Z"))
	data.NotAfter = types.StringValue(cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"))

	sha1Fp, sha256Fp := computeIdentityFingerprints(item.CertificateData)
	data.FingerprintSHA1 = types.StringValue(sha1Fp)
	data.FingerprintSHA256 = types.StringValue(sha256Fp)

	// Set key type (convert from internal codes)
	data.KeyType = types.StringValue(keyTypeFromKeychain(item.KeyType))
	data.KeySizeInBits = types.Int64Value(int64(item.KeySizeInBits))

	return nil
}

func (r *IdentityResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data IdentityResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	pkcs12Bytes, err := parsePKCS12(data.PKCS12Data.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error parsing PKCS#12 data",
			fmt.Sprintf("Could not parse PKCS#12 data: %s", err),
		)
		return
	}

	item := &keychain.IdentityItem{
		Label:      data.Label.ValueString(),
		PKCS12Data: pkcs12Bytes,
	}

	err = r.keychain.AddIdentity(item, data.Password.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating identity",
			fmt.Sprintf("Could not create identity: %s", err),
		)
		return
	}

	data.ID = types.StringValue(data.Label.ValueString())

	// Read back the identity to get certificate data and computed fields
	readItem, err := r.keychain.GetIdentity(data.Label.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading created identity",
			fmt.Sprintf("Could not read identity after creation: %s", err),
		)
		return
	}

	err = populateIdentityComputedFields(&data, readItem)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error parsing identity certificate",
			fmt.Sprintf("Could not parse certificate data: %s", err),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *IdentityResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data IdentityResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	item, err := r.keychain.GetIdentity(data.Label.ValueString())
	if err != nil {
		if keychain.IsItemNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError(
			"Error reading identity",
			fmt.Sprintf("Could not read identity: %s", err),
		)
		return
	}

	err = populateIdentityComputedFields(&data, item)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error parsing identity certificate",
			fmt.Sprintf("Could not parse certificate data: %s", err),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *IdentityResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data IdentityResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	pkcs12Bytes, err := parsePKCS12(data.PKCS12Data.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error parsing PKCS#12 data",
			fmt.Sprintf("Could not parse PKCS#12 data: %s", err),
		)
		return
	}

	// Delete existing and re-add (keychain doesn't have identity update)
	_ = r.keychain.DeleteIdentity(data.Label.ValueString())

	item := &keychain.IdentityItem{
		Label:      data.Label.ValueString(),
		PKCS12Data: pkcs12Bytes,
	}

	err = r.keychain.AddIdentity(item, data.Password.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating identity",
			fmt.Sprintf("Could not update identity: %s", err),
		)
		return
	}

	// Read back the identity to get certificate data and computed fields
	readItem, err := r.keychain.GetIdentity(data.Label.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading updated identity",
			fmt.Sprintf("Could not read identity after update: %s", err),
		)
		return
	}

	err = populateIdentityComputedFields(&data, readItem)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error parsing identity certificate",
			fmt.Sprintf("Could not parse certificate data: %s", err),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *IdentityResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data IdentityResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.keychain.DeleteIdentity(data.Label.ValueString())
	if err != nil {
		if keychain.IsItemNotFound(err) {
			return
		}
		resp.Diagnostics.AddError(
			"Error deleting identity",
			fmt.Sprintf("Could not delete identity: %s", err),
		)
		return
	}
}

func (r *IdentityResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// ID is the label
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("label"), req.ID)...)
}
