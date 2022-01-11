cc = meson.get_compiler('cpp')

sf_pkcs11_deps = [
    dependency('json-c'),
    dependency('libcrypto'),
    sf_client_dep
]

sf_pkcs11_lib = shared_library(
    'sf_pkcs11',
    'src/pkcs11-sf-client.cpp',
    'src/pkcs11-sf-json.cpp',
    'src/pkcs11-sf-module.cpp',
    'src/pkcs11-sf-object.cpp',
    'src/pkcs11-sf-session.cpp',
    'src/pkcs11-sf-slot.cpp',
    'src/pkcs11-sf-token.cpp',
    'src/pkcs11-sf-statics.cpp',
    include_directories : 'include',
    dependencies: sf_pkcs11_deps,
    install: get_option('lib-pkcs11')
)
