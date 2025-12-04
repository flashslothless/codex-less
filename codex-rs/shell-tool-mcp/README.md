# codex-shell-tool-mcp

A Rust launcher that wraps the `codex-exec-mcp-server` binary and its helpers. It picks the correct vendored artifacts for the current platform and forwards `--execve` and `--bash` to the MCP server.

## Usage

Build the crate and invoke the launcher (it forwards all additional arguments to `codex-exec-mcp-server`):

```bash
cargo run -p codex-shell-tool-mcp -- --help
```

The binary looks for a `vendor/` directory next to the executable (and falls back to the crate root). That directory is expected to contain per-target subdirectories with:

- `codex-exec-mcp-server`
- `codex-execve-wrapper`
- `bash/<variant>/bash` built for multiple glibc baselines and macOS releases.

Linux hosts read `/etc/os-release` to choose the closest matching Bash variant. macOS hosts use the Darwin major version (from `uname -r`) to pick a compatible build.

## Development

This crate is part of the Rust workspace. Use the standard tooling from the workspace root:

```bash
cd codex-rs
just fmt
just fix -p codex-shell-tool-mcp
cargo test -p codex-shell-tool-mcp
```

## Patched Bash

We carry `patches/bash-exec-wrapper.patch`, which adds `BASH_EXEC_WRAPPER` support to Bash. It applies cleanly to `a8a1c2fac029404d3f42cd39f5a20f24b6e4fe4b` from https://github.com/bminor/bash. To rebuild manually:

```bash
git clone https://github.com/bminor/bash
git checkout a8a1c2fac029404d3f42cd39f5a20f24b6e4fe4b
git apply /path/to/patches/bash-exec-wrapper.patch
./configure --without-bash-malloc
make -j"$(nproc)"
```
