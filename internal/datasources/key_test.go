//go:build darwin

package datasources_test

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/sparkworx/terraform-provider-keychain/internal/provider"
)

func TestAccKeyDataSource_basic(t *testing.T) {
	provider.SkipIfNoTestKeychain(t)

	label := "test-acc-ds-key-basic"
	keyData := base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901"))

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: provider.ProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				// First, create a resource to read
				Config: testAccKeyResourceConfig(label, keyData),
			},
			{
				// Then read it with the data source
				Config: testAccKeyResourceAndDataSourceConfig(label, keyData),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.keychain_key.test", "label", label),
					resource.TestCheckResourceAttr("data.keychain_key.test", "id", label),
					resource.TestCheckResourceAttrSet("data.keychain_key.test", "key_data"),
					resource.TestCheckResourceAttr("data.keychain_key.test", "key_class", "symmetric"),
					resource.TestCheckResourceAttr("data.keychain_key.test", "key_type", "aes"),
					resource.TestCheckResourceAttr("data.keychain_key.test", "key_size_bits", "256"),
					resource.TestCheckResourceAttr("data.keychain_key.test", "extractable", "true"),
				),
			},
		},
	})
}

func TestAccKeyDataSource_readExisting(t *testing.T) {
	provider.SkipIfNoTestKeychain(t)

	label := "test-acc-ds-key-existing"
	keyData := base64.StdEncoding.EncodeToString([]byte("abcdefghijklmnopqrstuvwxyz012345"))

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: provider.ProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				// Create a resource and data source in the same config
				Config: testAccKeyResourceAndDataSourceConfig(label, keyData),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Verify data source reads the same values as the resource
					resource.TestCheckResourceAttrPair(
						"keychain_key.test", "label",
						"data.keychain_key.test", "label",
					),
					resource.TestCheckResourceAttrPair(
						"keychain_key.test", "key_class",
						"data.keychain_key.test", "key_class",
					),
					resource.TestCheckResourceAttrPair(
						"keychain_key.test", "key_type",
						"data.keychain_key.test", "key_type",
					),
					resource.TestCheckResourceAttrPair(
						"keychain_key.test", "key_size_bits",
						"data.keychain_key.test", "key_size_bits",
					),
				),
			},
		},
	})
}

func testAccKeyResourceConfig(label, keyData string) string {
	return provider.TestProviderConfig() + fmt.Sprintf(`
resource "keychain_key" "test" {
  label         = %q
  key_data      = %q
  key_class     = "symmetric"
  key_type      = "aes"
  key_size_bits = 256
  extractable   = true
  permanent     = true
}
`, label, keyData)
}

func testAccKeyResourceAndDataSourceConfig(label, keyData string) string {
	return testAccKeyResourceConfig(label, keyData) + fmt.Sprintf(`
data "keychain_key" "test" {
  label = %q

  depends_on = [keychain_key.test]
}
`, label)
}
