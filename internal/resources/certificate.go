package resources

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
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
	_ resource.Resource                = &CertificateResource{}
	_ resource.ResourceWithImportState = &CertificateResource{}
)

type CertificateResource struct {
	keychain *keychain.Keychain
}

type CertificateResourceModel struct {
	ID                types.String `tfsdk:"id"`
	Label             types.String `tfsdk:"label"`
	Certificate       types.String `tfsdk:"certificate"`
	Subject           types.String `tfsdk:"subject"`
	Issuer            types.String `tfsdk:"issuer"`
	SerialNumber      types.String `tfsdk:"serial_number"`
	NotBefore         types.String `tfsdk:"not_before"`
	NotAfter          types.String `tfsdk:"not_after"`
	FingerprintSHA1   types.String `tfsdk:"fingerprint_sha1"`
	FingerprintSHA256 types.String `tfsdk:"fingerprint_sha256"`
}

func NewCertificateResource() resource.Resource {
	return &CertificateResource{}
}

func (r *CertificateResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_certificate"
}

func (r *CertificateResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a certificate item in the macOS Keychain.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The unique identifier for this resource (the label).",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"label": schema.StringAttribute{
				Description: "A human-readable label for the certificate. This is the unique identifier.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"certificate": schema.StringAttribute{
				Description: "The certificate data in PEM or DER format (base64 encoded if DER).",
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
		},
	}
}

func (r *CertificateResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

// parseCertificate parses PEM or base64-encoded DER certificate data and returns the DER bytes and parsed cert
func parseCertificate(certData string) ([]byte, *x509.Certificate, error) {
	// Try PEM first
	block, _ := pem.Decode([]byte(certData))
	var derBytes []byte

	if block != nil && block.Type == "CERTIFICATE" {
		derBytes = block.Bytes
	} else {
		// Try base64-encoded DER
		var err error
		derBytes, err = base64.StdEncoding.DecodeString(certData)
		if err != nil {
			// Maybe it's raw DER (unlikely in text form, but try)
			derBytes = []byte(certData)
		}
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return derBytes, cert, nil
}

// computeFingerprints computes SHA1 and SHA256 fingerprints of DER data
func computeFingerprints(derBytes []byte) (sha1Hex, sha256Hex string) {
	sha1Sum := sha1.Sum(derBytes)
	sha256Sum := sha256.Sum256(derBytes)
	return hex.EncodeToString(sha1Sum[:]), hex.EncodeToString(sha256Sum[:])
}

// populateComputedFields fills in the computed certificate attributes
func populateComputedFields(data *CertificateResourceModel, cert *x509.Certificate, derBytes []byte) {
	data.Subject = types.StringValue(cert.Subject.String())
	data.Issuer = types.StringValue(cert.Issuer.String())
	data.SerialNumber = types.StringValue(cert.SerialNumber.String())
	data.NotBefore = types.StringValue(cert.NotBefore.UTC().Format("2006-01-02T15:04:05Z"))
	data.NotAfter = types.StringValue(cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"))

	sha1Fp, sha256Fp := computeFingerprints(derBytes)
	data.FingerprintSHA1 = types.StringValue(sha1Fp)
	data.FingerprintSHA256 = types.StringValue(sha256Fp)
}

func (r *CertificateResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data CertificateResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	derBytes, cert, err := parseCertificate(data.Certificate.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error parsing certificate",
			fmt.Sprintf("Could not parse certificate data: %s", err),
		)
		return
	}

	item := &keychain.CertificateItem{
		Label:           data.Label.ValueString(),
		CertificateData: derBytes,
	}

	err = r.keychain.AddCertificate(item)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating certificate",
			fmt.Sprintf("Could not create certificate: %s", err),
		)
		return
	}

	data.ID = types.StringValue(data.Label.ValueString())
	// Keep the original certificate value from config (don't normalize)
	populateComputedFields(&data, cert, derBytes)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *CertificateResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data CertificateResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	item, err := r.keychain.GetCertificate(data.Label.ValueString())
	if err != nil {
		if keychain.IsItemNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError(
			"Error reading certificate",
			fmt.Sprintf("Could not read certificate: %s", err),
		)
		return
	}

	// Parse the certificate from keychain to get computed fields
	cert, err := x509.ParseCertificate(item.CertificateData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error parsing certificate",
			fmt.Sprintf("Could not parse certificate from keychain: %s", err),
		)
		return
	}

	// Check if the certificate in state matches the one in keychain
	// by comparing the DER bytes. If they match, preserve the state value
	// to avoid spurious diffs from format differences (PEM vs base64 DER)
	if !data.Certificate.IsNull() && !data.Certificate.IsUnknown() {
		stateDerBytes, _, stateErr := parseCertificate(data.Certificate.ValueString())
		if stateErr == nil {
			keychainDER := base64.StdEncoding.EncodeToString(item.CertificateData)
			stateDER := base64.StdEncoding.EncodeToString(stateDerBytes)
			if keychainDER != stateDER {
				// Certificate has changed externally, update state
				data.Certificate = types.StringValue(keychainDER)
			}
			// else: certificates match, keep the original state value
		}
	} else {
		// No prior state, use base64-encoded DER
		data.Certificate = types.StringValue(base64.StdEncoding.EncodeToString(item.CertificateData))
	}

	populateComputedFields(&data, cert, item.CertificateData)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *CertificateResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data CertificateResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	derBytes, cert, err := parseCertificate(data.Certificate.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error parsing certificate",
			fmt.Sprintf("Could not parse certificate data: %s", err),
		)
		return
	}

	// Delete existing and re-add (keychain doesn't have certificate update)
	_ = r.keychain.DeleteCertificate(data.Label.ValueString())

	item := &keychain.CertificateItem{
		Label:           data.Label.ValueString(),
		CertificateData: derBytes,
	}

	err = r.keychain.AddCertificate(item)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating certificate",
			fmt.Sprintf("Could not update certificate: %s", err),
		)
		return
	}

	// Keep the original certificate value from config (don't normalize)
	populateComputedFields(&data, cert, derBytes)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *CertificateResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data CertificateResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.keychain.DeleteCertificate(data.Label.ValueString())
	if err != nil {
		if keychain.IsItemNotFound(err) {
			return
		}
		resp.Diagnostics.AddError(
			"Error deleting certificate",
			fmt.Sprintf("Could not delete certificate: %s", err),
		)
		return
	}
}

func (r *CertificateResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// ID is the label
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("label"), req.ID)...)
}
