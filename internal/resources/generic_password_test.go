//go:build darwin

package resources_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/sparkworx/terraform-provider-keychain/internal/provider"
)

func TestAccGenericPassword_basic(t *testing.T) {
	provider.SkipIfNoTestKeychain(t)

	service := "test-acc-service-basic"
	account := "test-acc-account-basic"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: provider.ProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: testAccGenericPasswordConfig(service, account, "initial-password", "Initial Label", "Initial Description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("keychain_generic_password.test", "service", service),
					resource.TestCheckResourceAttr("keychain_generic_password.test", "account", account),
					resource.TestCheckResourceAttr("keychain_generic_password.test", "password", "initial-password"),
					resource.TestCheckResourceAttr("keychain_generic_password.test", "label", "Initial Label"),
					resource.TestCheckResourceAttr("keychain_generic_password.test", "description", "Initial Description"),
					resource.TestCheckResourceAttr("keychain_generic_password.test", "id", fmt.Sprintf("%s:%s", service, account)),
				),
			},
		},
	})
}

func TestAccGenericPassword_update(t *testing.T) {
	provider.SkipIfNoTestKeychain(t)

	service := "test-acc-service-update"
	account := "test-acc-account-update"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: provider.ProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: testAccGenericPasswordConfig(service, account, "initial-password", "Initial Label", "Initial Description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("keychain_generic_password.test", "password", "initial-password"),
					resource.TestCheckResourceAttr("keychain_generic_password.test", "label", "Initial Label"),
					resource.TestCheckResourceAttr("keychain_generic_password.test", "description", "Initial Description"),
				),
			},
			{
				Config: testAccGenericPasswordConfig(service, account, "updated-password", "Updated Label", "Updated Description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("keychain_generic_password.test", "password", "updated-password"),
					resource.TestCheckResourceAttr("keychain_generic_password.test", "label", "Updated Label"),
					resource.TestCheckResourceAttr("keychain_generic_password.test", "description", "Updated Description"),
				),
			},
		},
	})
}

func TestAccGenericPassword_import(t *testing.T) {
	provider.SkipIfNoTestKeychain(t)

	service := "test-acc-service-import"
	account := "test-acc-account-import"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: provider.ProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: testAccGenericPasswordConfig(service, account, "import-password", "Import Label", "Import Description"),
			},
			{
				ResourceName:      "keychain_generic_password.test",
				ImportState:       true,
				ImportStateId:     fmt.Sprintf("%s:%s", service, account),
				ImportStateVerify: true,
				// Password is sensitive and may not be verified on import
				ImportStateVerifyIgnore: []string{"password"},
			},
		},
	})
}

func TestAccGenericPassword_minimalConfig(t *testing.T) {
	provider.SkipIfNoTestKeychain(t)

	service := "test-acc-service-minimal"
	account := "test-acc-account-minimal"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: provider.ProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: testAccGenericPasswordConfigMinimal(service, account, "minimal-password"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("keychain_generic_password.test", "service", service),
					resource.TestCheckResourceAttr("keychain_generic_password.test", "account", account),
					resource.TestCheckResourceAttr("keychain_generic_password.test", "password", "minimal-password"),
				),
			},
		},
	})
}

func testAccGenericPasswordConfig(service, account, password, label, description string) string {
	return provider.TestProviderConfig() + fmt.Sprintf(`
resource "keychain_generic_password" "test" {
  service     = %q
  account     = %q
  password    = %q
  label       = %q
  description = %q
}
`, service, account, password, label, description)
}

func testAccGenericPasswordConfigMinimal(service, account, password string) string {
	return provider.TestProviderConfig() + fmt.Sprintf(`
resource "keychain_generic_password" "test" {
  service  = %q
  account  = %q
  password = %q
}
`, service, account, password)
}
