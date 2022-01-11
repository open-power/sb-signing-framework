project(
    'client-c++',
    'cpp',
    default_options: [
        'werror=true',
        'warning_level=3',
    ],
    version: '1.0'
)

cc = meson.get_compiler('cpp')

subdir('sf_utils')
subdir('sf_client_lib')
subdir('sf_pkcs11')

executable(
    'sf_client',
    'cli_main.cpp',
    dependencies: [
        sf_client_dep
    ],
    install: true
)
