# codex-shell-tool-mcp

A Rust MCP server that provides shell, file, and HTTP fetch tools over STDIO. It reuses the vendored Bash selector to choose a compatible shell for the host platform and exposes a background-aware command runner alongside file helpers.

## Usage

Run the server directly over STDIO. The process blocks until the MCP client disconnects:

```bash
cargo run -p codex-shell-tool-mcp -- --root /your/workspace
```

The binary looks for a `vendor/` directory next to the executable (and falls back to the crate root). That directory is expected to contain per-target subdirectories with:

- `bash/<variant>/bash` built for multiple glibc baselines and macOS releases.

Linux hosts read `/etc/os-release` to choose the closest matching Bash variant. macOS hosts use the Darwin major version (from `uname -r`) to pick a compatible build. You can bypass the selector by passing `--bash /path/to/bash`.

### Tools

- **read**: Read a file within `--root` as UTF-8 or base64.
- **write**: Create or overwrite a file with UTF-8 or base64 input.
- **edit**: Replace the first occurrence of a string in a file.
- **bash**: Run a shell command in the foreground or background (returns a `session_id`).
- **bash-output**: Stream buffered output from a background session.
- **kill-shell**: Send SIGTERM to a background session.
- **web-fetch**: Fetch HTTP/HTTPS responses with an optional timeout.

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
