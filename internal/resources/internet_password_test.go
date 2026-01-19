//go:build darwin

package resources_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/sparkworx/terraform-provider-keychain/internal/provider"
)

func TestAccInternetPassword_basic(t *testing.T) {
	provider.SkipIfNoTestKeychain(t)

	server := "test-acc-server-basic.example.com"
	account := "test-acc-account-basic"
	protocol := "https"
	port := 443

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: provider.ProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: testAccInternetPasswordConfig(server, account, protocol, port, "initial-password", "Initial Label"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("keychain_internet_password.test", "server", server),
					resource.TestCheckResourceAttr("keychain_internet_password.test", "account", account),
					resource.TestCheckResourceAttr("keychain_internet_password.test", "protocol", protocol),
					resource.TestCheckResourceAttr("keychain_internet_password.test", "port", fmt.Sprintf("%d", port)),
					resource.TestCheckResourceAttr("keychain_internet_password.test", "password", "initial-password"),
					resource.TestCheckResourceAttr("keychain_internet_password.test", "label", "Initial Label"),
					resource.TestCheckResourceAttr("keychain_internet_password.test", "id", fmt.Sprintf("%s:%s:%s:%d", server, account, protocol, port)),
				),
			},
		},
	})
}

func TestAccInternetPassword_update(t *testing.T) {
	provider.SkipIfNoTestKeychain(t)

	server := "test-acc-server-update.example.com"
	account := "test-acc-account-update"
	protocol := "https"
	port := 443

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: provider.ProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: testAccInternetPasswordConfig(server, account, protocol, port, "initial-password", "Initial Label"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("keychain_internet_password.test", "password", "initial-password"),
					resource.TestCheckResourceAttr("keychain_internet_password.test", "label", "Initial Label"),
				),
			},
			{
				Config: testAccInternetPasswordConfig(server, account, protocol, port, "updated-password", "Updated Label"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("keychain_internet_password.test", "password", "updated-password"),
					resource.TestCheckResourceAttr("keychain_internet_password.test", "label", "Updated Label"),
				),
			},
		},
	})
}

func TestAccInternetPassword_import(t *testing.T) {
	provider.SkipIfNoTestKeychain(t)

	server := "test-acc-server-import.example.com"
	account := "test-acc-account-import"
	protocol := "https"
	port := 443

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: provider.ProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: testAccInternetPasswordConfig(server, account, protocol, port, "import-password", "Import Label"),
			},
			{
				ResourceName:      "keychain_internet_password.test",
				ImportState:       true,
				ImportStateId:     fmt.Sprintf("%s:%s:%s:%d", server, account, protocol, port),
				ImportStateVerify: true,
				// Password is sensitive and may not be verified on import
				ImportStateVerifyIgnore: []string{"password"},
			},
		},
	})
}

func TestAccInternetPassword_protocols(t *testing.T) {
	provider.SkipIfNoTestKeychain(t)

	protocols := []struct {
		name     string
		protocol string
		port     int
	}{
		{"http", "http", 80},
		{"https", "https", 443},
		{"ftp", "ftp", 21},
		{"ssh", "ssh", 22},
	}

	for _, tc := range protocols {
		t.Run(tc.name, func(t *testing.T) {
			server := fmt.Sprintf("test-acc-server-%s.example.com", tc.name)
			account := fmt.Sprintf("test-acc-account-%s", tc.name)

			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: provider.ProtoV6ProviderFactories(),
				Steps: []resource.TestStep{
					{
						Config: testAccInternetPasswordConfigMinimal(server, account, tc.protocol, tc.port, "test-password"),
						Check: resource.ComposeAggregateTestCheckFunc(
							resource.TestCheckResourceAttr("keychain_internet_password.test", "server", server),
							resource.TestCheckResourceAttr("keychain_internet_password.test", "account", account),
							resource.TestCheckResourceAttr("keychain_internet_password.test", "protocol", tc.protocol),
							resource.TestCheckResourceAttr("keychain_internet_password.test", "port", fmt.Sprintf("%d", tc.port)),
						),
					},
				},
			})
		})
	}
}

func TestAccInternetPassword_minimalConfig(t *testing.T) {
	provider.SkipIfNoTestKeychain(t)

	server := "test-acc-server-minimal.example.com"
	account := "test-acc-account-minimal"
	protocol := "https"
	port := 443

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: provider.ProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: testAccInternetPasswordConfigMinimal(server, account, protocol, port, "minimal-password"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("keychain_internet_password.test", "server", server),
					resource.TestCheckResourceAttr("keychain_internet_password.test", "account", account),
					resource.TestCheckResourceAttr("keychain_internet_password.test", "protocol", protocol),
					resource.TestCheckResourceAttr("keychain_internet_password.test", "password", "minimal-password"),
				),
			},
		},
	})
}

func testAccInternetPasswordConfig(server, account, protocol string, port int, password, label string) string {
	return provider.TestProviderConfig() + fmt.Sprintf(`
resource "keychain_internet_password" "test" {
  server   = %q
  account  = %q
  protocol = %q
  port     = %d
  password = %q
  label    = %q
}
`, server, account, protocol, port, password, label)
}

func testAccInternetPasswordConfigMinimal(server, account, protocol string, port int, password string) string {
	return provider.TestProviderConfig() + fmt.Sprintf(`
resource "keychain_internet_password" "test" {
  server   = %q
  account  = %q
  protocol = %q
  port     = %d
  password = %q
}
`, server, account, protocol, port, password)
}
