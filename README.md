Tools for NSOs (64-bit only)
- Convert ELF to NSO
```sh
elf2nso -o <output_nso_path> <path_to_elf>
```
- Convert NSO to ELF
```sh
nso2elf -o <output_elf_path> <path_to_nso>
```
- Convert NSO to NSO (for changing flags)
```sh
nso2nso -o <output_nso_path> <flags> <path_to_nso>
```

Thank you to [SwitchBrew](https://switchbrew.org/wiki/NSO0) for the NSO documentation

Building
- Compiler with C++ 20 support
- CMake 3.21+ (you can probably edit the minimum version and go lower, but 3.21 is already old anyways)
- `elf.h` header (if building on Windows)

```sh
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build
```