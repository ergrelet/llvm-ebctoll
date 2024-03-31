# llvm-ebctoll

Portable and standalone utility to extract embedded LLVM bitcode from binaries
compiled with `-fembed-bitcode`.

Supported executable formats:

- PE
- ELF

Note that upstream LLVM doesn't save linker flags when `-fembed-bitcode` is used.

## Usage

Note: Poetry is used to manage dependencies and thus should be installed
beforehand.

```
poetry install
poetry run llvm-ebctoll bin.exe output_dir
```
