#ifndef __J_ARGS__H
#define __J_ARGS__H

#if __cplusplus < 202002L
#error "args library uses C++20 features"
#else

#include <algorithm>
#include <iostream>
#include <iterator>
#include <memory>
#include <ranges>
#include <sstream>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <vector>

namespace views = std::ranges::views;

namespace args {

class parser;

struct flag {
  private:
  std::string m_lname;
  std::string m_sname;
  std::string m_desc;
  bool m_bool;
  bool m_req;
  friend class parser;

  public:
  flag() : m_lname(""), m_sname(""), m_desc(""), m_bool(false), m_req(false) {}

  flag& name(const std::string& name)
  {
    m_lname = name;
    return *this;
  }

  flag& short_name(const std::string& name)
  {
    m_sname = name;
    return *this;
  }

  flag& description(const std::string& desc)
  {
    m_desc = desc;
    return *this;
  }

  flag& required()
  {
    m_req = true;
    return *this;
  }

  flag& boolean()
  {
    m_bool = true;
    return *this;
  }
};

class subcommand {
  private:
  std::string m_name;
  std::string m_desc;
  std::vector<std::shared_ptr<subcommand> > m_allowed;
  friend class parser;

  public:
  subcommand() {}

  subcommand& name(const std::string& n)
  {
    m_name = n;
    return *this;
  }

  subcommand& description(const std::string& d)
  {
    m_desc = d;
    return *this;
  }

  template <typename... Args>
  subcommand& subcommands(Args&&... subs)
  {
    auto names =
        std::vector<std::common_type_t<Args...> >{std::forward<Args>(subs)...};
    for (const auto& n : names) {
      auto ptr = std::make_shared<subcommand>();
      ptr->m_name = n;
      m_allowed.push_back(ptr);
    }
    return *this;
  }

  subcommand& add_subcommand()
  {
    m_allowed.push_back(std::make_shared<subcommand>());
    return *m_allowed.back();
  }
};

class parser {
  private:
  std::string m_title;
  std::string m_desc;
  std::string m_version;
  std::vector<flag> m_flags;
  std::vector<std::shared_ptr<subcommand> > m_subs;
  std::unordered_map<std::string, std::string> m_values;
  std::vector<std::string> m_sub_vals;
  bool m_require_subs;
  bool m_help_enabled;

  bool has_flag(const std::string& key) const
  {
    auto it = std::find_if(m_flags.begin(), m_flags.end(),
                           [&](const auto& f) { return f.m_lname == key; });

    return it != m_flags.end();
  }

  const flag& get_flag(const std::string& key) const
  {
    auto it = std::find_if(m_flags.begin(), m_flags.end(),
                           [&](const auto& f) { return f.m_lname == key; });

    return *it;
  }

  bool validate_required_flags() const
  {
    auto required_view = m_flags |
                         views::filter([&](flag f) { return f.m_req; }) |
                         views::transform([&](flag f) { return f.m_lname; });
    auto required_flags =
        std::vector<std::string>(required_view.begin(), required_view.end());

    auto given_it = views::keys(m_values);
    auto given_flags =
        std::vector<std::string>(given_it.begin(), given_it.end());

    std::vector<std::string> intersection;
    std::ranges::set_intersection(required_flags, given_flags,
                                  std::back_inserter(intersection));

    return intersection.size() == required_flags.size();
  }

  bool validate_required_subcommands() const
  {
    return !m_require_subs || !m_sub_vals.empty();
  }

  int format_subcommand(const subcommand& s, int max_len, int level = 0) const
  {
    std::stringstream ss;
    ss << "    " << std::string(level * 4, ' ') << s.m_name;
    auto str = ss.str();

    int new_max_len = (str.length() > max_len) ? str.length() : max_len;
    for (auto sub : s.m_allowed) {
      new_max_len = format_subcommand(*sub, new_max_len, level + 1);
    }

    return new_max_len;
  }

  void print_subcommand(const subcommand& s, int max_len, int level = 0) const
  {
    std::stringstream ss;
    ss << "    " << std::string(level * 4, ' ') << s.m_name;
    auto str = ss.str();
    std::cout << str << std::string((max_len + 4) - str.length(), ' ')
              << s.m_desc << std::endl;

    for (auto sub : s.m_allowed) {
      print_subcommand(*sub, max_len, level + 1);
    }
  }

  public:
  parser(const std::string& title, const std::string& desc,
         const std::string& version = "")
      : m_title(title),
        m_desc(desc),
        m_version(version),
        m_flags(),
        m_require_subs(false),
        m_help_enabled(false)
  {
  }

  flag& add_flag()
  {
    m_flags.push_back(flag{});
    return m_flags.back();
  }

  subcommand& add_subcommand()
  {
    m_subs.push_back(std::make_shared<subcommand>());
    return *m_subs.back();
  }

  void enable_help()
  {
    add_flag()
        .name("help")
        .short_name("h")
        .description("Show this page")
        .boolean();
    m_help_enabled = true;
  }

  void require_subcommands() { m_require_subs = true; }

  void print_help() const
  {
    if (!m_help_enabled) {
      return;
    }

    std::cout << m_title;
    if (!m_version.empty()) {
      std::cout << " v" << m_version;
    }
    std::cout << std::endl << m_desc << std::endl << std::endl;
    std::cout << "Usage: " << m_title;
    if (m_subs.size() > 0) {
      std::cout << " [subcommands...]";
    }
    std::cout << " [options...]" << std::endl << std::endl;

    std::cout << "Subcommands:" << std::endl << std::endl;
    int max_len = 0;
    for (const auto& s : m_subs) {
      max_len = format_subcommand(*s, max_len);
    }
    for (const auto& s : m_subs) {
      print_subcommand(*s, max_len);
      std::cout << std::endl;
    }

    std::cout << "Options:" << std::endl;
    max_len = 0;
    std::vector<std::string> prefixes;
    for (const auto& f : m_flags) {
      std::stringstream ss;
      ss << "    ";
      if (!f.m_sname.empty()) {
        ss << "-" << f.m_sname << "|";
      }
      ss << "--" << f.m_lname;
      if (!f.m_bool) {
        ss << " <" << f.m_lname << ">";
      }
      auto str = ss.str();
      max_len = (str.length() > max_len) ? str.length() : max_len;
      prefixes.push_back(str);
    }
    for (int i = 0; i < m_flags.size(); i++) {
      const auto& f = m_flags[i];
      const auto& p = prefixes[i];

      std::cout << p;
      std::cout << "  " << std::string(max_len - p.length(), ' ') << f.m_desc;
      if (f.m_req) {
        std::cout << " (required)";
      }
      std::cout << std::endl;
    }
  }

  bool parse(int argc, char** argv)
  {
    bool at_subs = true;
    std::shared_ptr<subcommand> sub;

    for (int i = 1; i < argc; i++) {
      if (at_subs && !std::string(argv[i]).starts_with("-")) {
        auto sub_s = std::string(argv[i]);

        std::vector<std::shared_ptr<subcommand> > arr;
        if (sub.get() == nullptr) {
          arr = m_subs;
        }
        else {
          arr = sub->m_allowed;
        }

        auto it = std::find_if(arr.begin(), arr.end(),
                               [&](std::shared_ptr<subcommand> const& s) {
                                 return s->m_name == sub_s;
                               });
        if (it == arr.end()) {
          return false;
        }
        sub = *it;

        m_sub_vals.push_back(sub_s);
        continue;
      }

      std::string arg = argv[i];
      if (arg.starts_with("-")) {
        at_subs = false;
        if (arg.starts_with("--")) {
          auto name = arg.replace(0, 2, "");
          if (!has_flag(name)) {
            print_help();
            return false;
          }

          const auto& flag = get_flag(name);
          if (flag.m_bool) {
            m_values.insert({name, "true"});
          }
          else {
            std::string value = argv[i + 1];
            m_values.insert({name, value});
          }
        }
        else {
          auto name = arg.replace(0, 1, "");

          for (char c : name) {
            auto it =
                std::find_if(m_flags.begin(), m_flags.end(),
                             [&](const auto& f) { return f.m_sname == &c; });

            if (it == m_flags.end()) {
              print_help();
              return false;
            }

            const auto& flag = get_flag((*it).m_lname);
            if (flag.m_bool) {
              m_values.insert({flag.m_lname, "true"});
            }
            else {
              std::string value = argv[i + 1];
              m_values.insert({flag.m_lname, value});
            }
          }
        }
      }
    }

    if (!validate_required_flags() || !validate_required_subcommands() ||
        has("help")) {
      print_help();
      return false;
    }

    return true;
  }

  const std::vector<std::string> subs() const { return m_sub_vals; }

  bool has(const std::string& key) const { return m_values.contains(key); }

  const std::string& get(const std::string& key) const
  {
    return m_values.at(key);
  }

  template <typename T>
  T get_as(const std::string& key) const
  {
    auto val = get(key);
    if constexpr (std::is_integral_v<T> && std::is_same_v<T, bool>) {
      return val == "true";
    }
    else if constexpr (std::is_integral_v<T>) {
      return std::stoi(val);
    }
  }

  void dump() const
  {
    std::cout << "args::parser (" << this << ") {" << std::endl;

    std::cout << "  subs: [ ";
    for (auto s : m_sub_vals) {
      std::cout << "\"" << s << "\" ";
    }
    std::cout << "]" << std::endl;

    std::cout << "  flags: {" << std::endl;
    for (auto kv : m_values) {
      std::cout << "    " << kv.first << ": ";
      const auto& flag = get_flag(kv.first);
      if (flag.m_bool) {
        std::cout << "true" << std::endl;
      }
      else {
        std::cout << "\"" << kv.second << "\"" << std::endl;
      }
    }
    std::cout << "  }" << std::endl;
    std::cout << "}" << std::endl;
  }
};

}  // namespace args

#endif  // C++20
#endif  // __J_ARGS__H
