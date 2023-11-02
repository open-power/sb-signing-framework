cc = meson.get_compiler('cpp')

sf_client_deps = [
    libjson_c_dep,
    libcrypto_dep,
    libcurl_dep,
    libssl_dep,
    sf_utils_dep
]


lib_sf_client = static_library(
    'sf_client',
    'sf_client.cpp',
    'sf_curl.cpp',
    'sf_json.cpp',
    include_directories : 'include',
    dependencies: sf_client_deps
)

sf_client_dep = declare_dependency(
    dependencies: sf_client_deps,
    include_directories: 'include',
    link_with: lib_sf_client
)
