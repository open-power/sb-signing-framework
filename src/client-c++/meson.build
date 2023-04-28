project(
    'client-c++',
    'cpp',
    default_options: [
        'cpp_std=c++11',
        'c_std=c11',
        'werror=true',
        'warning_level=3',
    ],
    version: '1.0'
)

if get_option('getopt_long') == false
  add_global_arguments('-DNO_GETOPT_LONG', language: 'cpp')
endif

cc = meson.get_compiler('cpp')

libcrypto_dep = dependency('libcrypto', required : false)
if not libcrypto_dep.found()
  libcrypto_dep = cc.find_library('crypto', required : false )
endif

libssl_dep = dependency('libssl', required : false)
if not libssl_dep.found()
  libssl_dep = cc.find_library('ssl', required : false )
endif

libjson_c_dep = dependency('json-c', required : false)

if get_option('homebrew') == true
  # The curl library shipped in MacOS does not have sftp support.
  # The homebrew package 'curl-openssl' contains the required library, but is not included in the
  # default library path
  libcurl_dep = cc.find_library('libcurl', dirs: '/usr/local/opt/curl/lib', required: true)
  libssh_dep = cc.find_library('libssh2', dirs: '/usr/local/opt/libssh2/lib', required: true)
else
  libcurl_dep = dependency('libcurl', required : false)
  if not libcurl_dep.found()
    libcurl_dep = cc.find_library('curl', required : false )
  endif
endif

subdir('sf_utils')
subdir('sf_client_lib')

if get_option('lib-pkcs11') == true
  subdir('sf_pkcs11')
endif

executable(
    'sf_client',
    'cli_main.cpp',
    dependencies: [
        sf_client_dep
    ],
    install: true
)
