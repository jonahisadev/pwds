#include "util.hpp"

#include <termios.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <iostream>
#include <regex>
#include <sstream>
#include <string>

#include "pstream/pstream.h"

namespace fs = std::filesystem;

namespace pwds {
namespace util {

void tty_echo(bool shouldEcho)
{
  struct termios tty;
  tcgetattr(STDIN_FILENO, &tty);
  if (shouldEcho) {
    tty.c_lflag |= ECHO;
  }
  else {
    tty.c_lflag &= ~ECHO;
  }
  tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}

std::string prompt_password(const std::string& p)
{
  std::string password;
  std::cout << p;
  util::tty_echo(false);
  std::getline(std::cin, password);
  util::tty_echo(true);
  std::cout << std::endl;
  return password;
}

std::string prompt(const std::string& p)
{
  std::string response;
  std::cout << p;
  std::getline(std::cin, response);
  std::cout << std::endl;
  return response;
}

std::string config_dir()
{
  std::string home_dir = std::getenv("HOME");
  return (fs::path(home_dir) / ".pwd").string();
}

std::string shell_command(const std::string& cmd)
{
  std::string line;
  std::string result;
  redi::ipstream proc(cmd, redi::pstreams::pstdout);
  while (std::getline(proc.out(), line)) {
    result += line;
  }
  return result;
}

std::string increment_master_alias(const std::string& alias)
{
  std::regex rgx("__pwd_master_(\\d+)");
  std::smatch matches;

  if (std::regex_search(alias, matches, rgx)) {
    int version = std::stoi(matches[1]);
    version++;
    return std::format("__pwd_master_{}", version);
  }

  return "";
}

std::string current_time()
{
  using namespace std::chrono;

  auto now = system_clock::now();
  std::stringstream ss;
  ss << std::format("{:%FT%TZ}", now);
  return ss.str();
}

}  // namespace util
}  // namespace pwds
