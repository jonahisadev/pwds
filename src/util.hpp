#pragma once

#include <string>

namespace util {

void tty_echo(bool shouldEcho);
std::string prompt_password(const std::string& p);
std::string config_dir();
std::string shell_command(const std::string& cmd);
std::string increment_master_alias(const std::string& alias);

}  // namespace util
