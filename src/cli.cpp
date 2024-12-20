#include "cli.hpp"

#include "args/args.hpp"

namespace pwds {

args::parser create_parser()
{
  args::parser parser("vault", "Manage secrets from the CLI", "0.1.0");
  parser.enable_help();

  auto& vaultSub =
      parser.add_subcommand().name("vault").description("Manage vaults");
  vaultSub.add_subcommand().name("create").description("Create a new vault");
  vaultSub.add_subcommand().name("list").description("List available vaults");
  vaultSub.add_subcommand().name("select").description(
      "Select a vault to be treated as the default");
  vaultSub.add_subcommand().name("rotate").description(
      "Rotate vault master key and re-encrypt secrets");
  vaultSub.add_subcommand().name("persist").description(
      "Persist password in encrypted file");
  vaultSub.add_subcommand().name("sync").description(
      "Sync secrets with the cloud");

  auto& secretSub = parser.add_subcommand().name("secret").description(
      "Create, set and retreive secrets from a vault");
  secretSub.add_subcommand().name("create").description("Create a secret");
  secretSub.add_subcommand().name("list").description("List available secrets");
  secretSub.add_subcommand().name("get").description("Retreive a secret value");
  secretSub.add_subcommand().name("set").description(
      "Update an existing secret");
  secretSub.add_subcommand().name("delete").description("Delete a secret");

  auto& configSub = parser.add_subcommand().name("config").description(
      "Make changes to configuration");
  configSub.add_subcommand()
      .name("sync-url")
      .description("Set syncing server URL");

  parser.add_flag().name("name").short_name("n");
  parser.add_flag().name("value");
  parser.add_flag().name("pwfile").short_name("p");
  parser.add_flag().name("local").boolean();

  return parser;
}

}  // namespace pwds
