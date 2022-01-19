# Dependencies

- meson
- g++/clang++
- cmake
- json-c
- openssl
- curl

# Compile

Only building sf_client:
```
meson build -Dlib-pkcs11=false
ninja -C build
```

Building sf_client and the pkcs11 shared library module:
```
meson build -Dlib-pkcs11=true
ninja -C build
```

# Install

```
meson install
```
