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

if( get_option('ignore-deprecated') == true )
  add_project_arguments('-Wno-deprecated-declarations', language: 'cpp')
endif

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

if '' != get_option('libcurl')
  # The curl library available from package managers may not have sftp support.
  # Allow the developer to manually specify a library path.
  # Some common paths:
  # /usr/local/opt/libcurl/lib
  # /usr/local/lib
  libcurl_dep = cc.find_library('libcurl', dirs: get_option('libcurl'), required: true)
else
  libcurl_dep = dependency('libcurl', required : false)
  if not libcurl_dep.found()
    libcurl_dep = cc.find_library('curl', required : true )
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
