package datasources

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/sparkworx/terraform-provider-keychain/internal/keychain"
)

var _ datasource.DataSource = &IdentityDataSource{}

type IdentityDataSource struct {
	keychain *keychain.Keychain
}

type IdentityDataSourceModel struct {
	ID                types.String `tfsdk:"id"`
	Label             types.String `tfsdk:"label"`
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

func NewIdentityDataSource() datasource.DataSource {
	return &IdentityDataSource{}
}

func (d *IdentityDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_identity"
}

func (d *IdentityDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads an identity (certificate + private key) item from the macOS Keychain.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The unique identifier for this data source (the label).",
				Computed:    true,
			},
			"label": schema.StringAttribute{
				Description: "The label of the identity to look up.",
				Required:    true,
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

func (d *IdentityDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *IdentityDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data IdentityDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	item, err := d.keychain.GetIdentity(data.Label.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading identity",
			fmt.Sprintf("Could not read identity with label=%q: %s",
				data.Label.ValueString(), err),
		)
		return
	}

	// Parse the certificate to get subject/issuer/dates
	cert, err := x509.ParseCertificate(item.CertificateData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error parsing certificate",
			fmt.Sprintf("Could not parse certificate data: %s", err),
		)
		return
	}

	data.ID = types.StringValue(data.Label.ValueString())
	data.Subject = types.StringValue(cert.Subject.String())
	data.Issuer = types.StringValue(cert.Issuer.String())
	data.SerialNumber = types.StringValue(cert.SerialNumber.String())
	data.NotBefore = types.StringValue(cert.NotBefore.UTC().Format("2006-01-02T15:04:05Z"))
	data.NotAfter = types.StringValue(cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"))

	// Compute fingerprints
	sha1Sum := sha1.Sum(item.CertificateData)
	sha256Sum := sha256.Sum256(item.CertificateData)
	data.FingerprintSHA1 = types.StringValue(hex.EncodeToString(sha1Sum[:]))
	data.FingerprintSHA256 = types.StringValue(hex.EncodeToString(sha256Sum[:]))

	// Set key type (convert from internal codes)
	data.KeyType = types.StringValue(keyTypeFromKeychainDS(item.KeyType))
	data.KeySizeInBits = types.Int64Value(int64(item.KeySizeInBits))

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
