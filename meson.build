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
  'src/base64.cpp',
  'src/vault.cpp',
  'src/util.cpp',
  'src/config.cpp',
  'src/cli.cpp',
  'src/cert.cpp',
  'src/crypto.cpp'
]
incdir = include_directories('include')
deps = [
  compiler.find_library('libsoftokn3', dirs: ['/usr/lib/']),
  dependency('sqlite3'),
  dependency('openssl')
]

executable('pwds', sources,
  dependencies: deps,
  include_directories: incdir,
)
