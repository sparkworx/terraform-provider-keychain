//go:build darwin

package datasources_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/sparkworx/terraform-provider-keychain/internal/provider"
)

func TestAccGenericPasswordDataSource_basic(t *testing.T) {
	provider.SkipIfNoTestKeychain(t)

	service := "test-acc-ds-service-basic"
	account := "test-acc-ds-account-basic"
	password := "datasource-test-password"
	label := "DataSource Test Label"
	description := "DataSource Test Description"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: provider.ProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				// First, create a resource to read
				Config: testAccGenericPasswordResourceConfig(service, account, password, label, description),
			},
			{
				// Then read it with the data source
				Config: testAccGenericPasswordResourceAndDataSourceConfig(service, account, password, label, description),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.keychain_generic_password.test", "service", service),
					resource.TestCheckResourceAttr("data.keychain_generic_password.test", "account", account),
					resource.TestCheckResourceAttr("data.keychain_generic_password.test", "password", password),
					resource.TestCheckResourceAttr("data.keychain_generic_password.test", "label", label),
					resource.TestCheckResourceAttr("data.keychain_generic_password.test", "description", description),
					resource.TestCheckResourceAttr("data.keychain_generic_password.test", "id", fmt.Sprintf("%s:%s", service, account)),
				),
			},
		},
	})
}

func TestAccGenericPasswordDataSource_readExisting(t *testing.T) {
	provider.SkipIfNoTestKeychain(t)

	service := "test-acc-ds-service-existing"
	account := "test-acc-ds-account-existing"
	password := "existing-password"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: provider.ProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				// Create a resource and data source in the same config
				Config: testAccGenericPasswordResourceAndDataSourceConfig(service, account, password, "", ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Verify data source reads the same values as the resource
					resource.TestCheckResourceAttrPair(
						"keychain_generic_password.test", "service",
						"data.keychain_generic_password.test", "service",
					),
					resource.TestCheckResourceAttrPair(
						"keychain_generic_password.test", "account",
						"data.keychain_generic_password.test", "account",
					),
					resource.TestCheckResourceAttrPair(
						"keychain_generic_password.test", "password",
						"data.keychain_generic_password.test", "password",
					),
				),
			},
		},
	})
}

func testAccGenericPasswordResourceConfig(service, account, password, label, description string) string {
	config := provider.TestProviderConfig() + fmt.Sprintf(`
resource "keychain_generic_password" "test" {
  service  = %q
  account  = %q
  password = %q
`, service, account, password)

	if label != "" {
		config += fmt.Sprintf(`  label = %q
`, label)
	}
	if description != "" {
		config += fmt.Sprintf(`  description = %q
`, description)
	}

	config += "}\n"
	return config
}

func testAccGenericPasswordResourceAndDataSourceConfig(service, account, password, label, description string) string {
	return testAccGenericPasswordResourceConfig(service, account, password, label, description) + fmt.Sprintf(`
data "keychain_generic_password" "test" {
  service = %q
  account = %q

  depends_on = [keychain_generic_password.test]
}
`, service, account)
}
