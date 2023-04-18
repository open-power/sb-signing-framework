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
