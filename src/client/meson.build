project(
    'sb-signing-framwork',
    'c',
    default_options: [
        'c_std=gnu99',
        'werror=true',
        'warning_level=3',
    ],
    version: '1.0'
)

cc = meson.get_compiler('c')

executable(
    'sf_client',
    'client.c',
    'pscp_json.c',
    'pscp_sftp.c',
    c_args: [
        '-Wno-unused-parameter',
        '-Wno-sign-compare',
    ],
    dependencies: [
        dependency('json-c'),
        dependency('libcrypto'),
        dependency('libcurl'),
        dependency('libssl'),
        cc.find_library('m'),
    ],
    install: true
)

executable(
    'sftp-test',
    'pscp_sftp_test.c',
    'pscp_sftp.c',
    c_args: [
        '-Wno-unused-parameter',
    ],
    dependencies: [
        dependency('libcurl'),
    ]
)
