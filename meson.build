project('pwd', 'cpp',
  version: '0.0.1',
  license: 'MIT',
  default_options: [ 'cpp_std=c++20' ]
)

compiler = meson.get_compiler('cpp')

sources = [
  'src/main.cpp',
  'src/p11.cpp',
  'src/key.cpp',
  'src/vault.cpp',
  'src/util.cpp',
  'src/config.cpp',
  'src/cli.cpp',
  'src/crypto.cpp',
  'src/sync.cpp'
]
incdir = include_directories('include', '/usr/local/include/botan-3')
deps = [
  compiler.find_library('libsoftokn3', dirs: ['/usr/lib/']),
  compiler.find_library('libbotan-3', dirs: ['/usr/local/lib']),
  compiler.find_library('libcurl', dirs: ['/usr/lib']),
  dependency('sqlite3'),
]

executable('pwds', sources,
  dependencies: deps,
  include_directories: incdir,
)
