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

if get_option('secure_heap') == false
  add_global_arguments('-DNO_SECURE_HEAP', language: 'cpp')
endif

cc = meson.get_compiler('cpp')

git_version = vcs_tag(command: ['git', 'rev-parse', '--short', 'HEAD'],
                      input : 'git_hash.h.in',
                      output : 'git_hash.h',
                      replace_string: '@GIT_VERSION@')

include_directories('build')

if( get_option('verbose') == true )
  add_global_arguments('-DDEBUG', language: 'cpp')
endif

libcrypto_dep = dependency('libcrypto', required : false)
if not libcrypto_dep.found()
  libcrypto_dep = cc.find_library('crypto', required : true )
endif

libssl_dep = dependency('libssl', required : false)
if not libssl_dep.found()
  libssl_dep = cc.find_library('ssl', required : true )
endif

libjson_c_dep = dependency('json-c', required : true)

libcurl_dep = dependency('libcurl', required : false)
if not libssl_dep.found()
  libcurl_dep = cc.find_library('curl', required : true )
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
