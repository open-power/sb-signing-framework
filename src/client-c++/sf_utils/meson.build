
cc = meson.get_compiler('cpp')

sf_utils_lib = static_library(
    'sf_utils',
    'sf_utils.cpp',
    include_directories : 'include'
)

sf_utils_dep = declare_dependency(
    include_directories: 'include',
    link_with: sf_utils_lib
)
