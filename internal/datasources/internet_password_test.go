//go:build darwin

package datasources_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/sparkworx/terraform-provider-keychain/internal/provider"
)

func TestAccInternetPasswordDataSource_basic(t *testing.T) {
	provider.SkipIfNoTestKeychain(t)

	server := "test-acc-ds-server-basic.example.com"
	account := "test-acc-ds-account-basic"
	protocol := "https"
	port := 443
	password := "datasource-test-password"
	label := "DataSource Test Label"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: provider.ProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				// First, create a resource to read
				Config: testAccInternetPasswordResourceConfig(server, account, protocol, port, password, label),
			},
			{
				// Then read it with the data source
				Config: testAccInternetPasswordResourceAndDataSourceConfig(server, account, protocol, port, password, label),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.keychain_internet_password.test", "server", server),
					resource.TestCheckResourceAttr("data.keychain_internet_password.test", "account", account),
					resource.TestCheckResourceAttr("data.keychain_internet_password.test", "protocol", protocol),
					resource.TestCheckResourceAttr("data.keychain_internet_password.test", "port", fmt.Sprintf("%d", port)),
					resource.TestCheckResourceAttr("data.keychain_internet_password.test", "password", password),
					resource.TestCheckResourceAttr("data.keychain_internet_password.test", "label", label),
					resource.TestCheckResourceAttr("data.keychain_internet_password.test", "id", fmt.Sprintf("%s:%s:%s:%d", server, account, protocol, port)),
				),
			},
		},
	})
}

func TestAccInternetPasswordDataSource_readExisting(t *testing.T) {
	provider.SkipIfNoTestKeychain(t)

	server := "test-acc-ds-server-existing.example.com"
	account := "test-acc-ds-account-existing"
	protocol := "https"
	port := 443
	password := "existing-password"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: provider.ProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				// Create a resource and data source in the same config
				Config: testAccInternetPasswordResourceAndDataSourceConfig(server, account, protocol, port, password, ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Verify data source reads the same values as the resource
					resource.TestCheckResourceAttrPair(
						"keychain_internet_password.test", "server",
						"data.keychain_internet_password.test", "server",
					),
					resource.TestCheckResourceAttrPair(
						"keychain_internet_password.test", "account",
						"data.keychain_internet_password.test", "account",
					),
					resource.TestCheckResourceAttrPair(
						"keychain_internet_password.test", "protocol",
						"data.keychain_internet_password.test", "protocol",
					),
					resource.TestCheckResourceAttrPair(
						"keychain_internet_password.test", "port",
						"data.keychain_internet_password.test", "port",
					),
					resource.TestCheckResourceAttrPair(
						"keychain_internet_password.test", "password",
						"data.keychain_internet_password.test", "password",
					),
				),
			},
		},
	})
}

func testAccInternetPasswordResourceConfig(server, account, protocol string, port int, password, label string) string {
	config := provider.TestProviderConfig() + fmt.Sprintf(`
resource "keychain_internet_password" "test" {
  server   = %q
  account  = %q
  protocol = %q
  port     = %d
  password = %q
`, server, account, protocol, port, password)

	if label != "" {
		config += fmt.Sprintf(`  label = %q
`, label)
	}

	config += "}\n"
	return config
}

func testAccInternetPasswordResourceAndDataSourceConfig(server, account, protocol string, port int, password, label string) string {
	return testAccInternetPasswordResourceConfig(server, account, protocol, port, password, label) + fmt.Sprintf(`
data "keychain_internet_password" "test" {
  server   = %q
  account  = %q
  protocol = %q
  port     = %d

  depends_on = [keychain_internet_password.test]
}
`, server, account, protocol, port)
}
