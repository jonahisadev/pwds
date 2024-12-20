#pragma once

#include <string>

namespace pwds {
namespace util {

void tty_echo(bool shouldEcho);
std::string prompt_password(const std::string& p);
std::string prompt(const std::string& p);
std::string config_dir();
std::string shell_command(const std::string& cmd);
std::string increment_master_alias(const std::string& alias);
std::string current_time();

}  // namespace util
}  // namespace pwds
