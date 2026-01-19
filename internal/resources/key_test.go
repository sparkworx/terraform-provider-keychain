//go:build darwin

package resources_test

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/sparkworx/terraform-provider-keychain/internal/provider"
)

func TestAccKey_basic(t *testing.T) {
	provider.SkipIfNoTestKeychain(t)

	label := "test-acc-key-basic"
	// 32 bytes for AES-256
	keyData := base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901"))

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: provider.ProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: testAccKeyConfig(label, keyData, "symmetric", "aes", 256),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("keychain_key.test", "label", label),
					resource.TestCheckResourceAttr("keychain_key.test", "id", label),
					resource.TestCheckResourceAttr("keychain_key.test", "key_class", "symmetric"),
					resource.TestCheckResourceAttr("keychain_key.test", "key_type", "aes"),
					resource.TestCheckResourceAttr("keychain_key.test", "key_size_bits", "256"),
					resource.TestCheckResourceAttr("keychain_key.test", "extractable", "true"),
					resource.TestCheckResourceAttr("keychain_key.test", "permanent", "true"),
				),
			},
		},
	})
}

func TestAccKey_update(t *testing.T) {
	provider.SkipIfNoTestKeychain(t)

	label := "test-acc-key-update"
	// Different key data for update test
	keyData1 := base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
	keyData2 := base64.StdEncoding.EncodeToString([]byte("abcdefghijklmnopqrstuvwxyz012345"))

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: provider.ProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: testAccKeyConfig(label, keyData1, "symmetric", "aes", 256),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("keychain_key.test", "label", label),
					resource.TestCheckResourceAttr("keychain_key.test", "key_data", keyData1),
				),
			},
			{
				Config: testAccKeyConfig(label, keyData2, "symmetric", "aes", 256),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("keychain_key.test", "label", label),
					resource.TestCheckResourceAttr("keychain_key.test", "key_data", keyData2),
				),
			},
		},
	})
}

func TestAccKey_import(t *testing.T) {
	provider.SkipIfNoTestKeychain(t)

	label := "test-acc-key-import"
	keyData := base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901"))

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: provider.ProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: testAccKeyConfig(label, keyData, "symmetric", "aes", 256),
			},
			{
				ResourceName:      "keychain_key.test",
				ImportState:       true,
				ImportStateId:     label,
				ImportStateVerify: true,
				// Key data format may differ after import, application_tag not stored in keychain
				ImportStateVerifyIgnore: []string{"key_data", "permanent", "application_tag"},
			},
		},
	})
}

func testAccKeyConfig(label, keyData, keyClass, keyType string, keySizeBits int) string {
	return provider.TestProviderConfig() + fmt.Sprintf(`
resource "keychain_key" "test" {
  label         = %q
  key_data      = %q
  key_class     = %q
  key_type      = %q
  key_size_bits = %d
  extractable   = true
  permanent     = true
}
`, label, keyData, keyClass, keyType, keySizeBits)
}
