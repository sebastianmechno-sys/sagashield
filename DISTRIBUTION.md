# Distribution Guide — sagashield

All supported ways to install and run SagaShield, for end users and developers.

## 1. Python: `pip install sagashield`

```bash
pip install sagashield
```

```python
from sagashield import SagaKernel, SecurityPolicy

kernel = SagaKernel(policy=SecurityPolicy(["./workspace"]))
kernel.begin_planning()
```

- Requires Python ≥ 3.8 (abi3 wheel, no compiler needed).
- Optional LangChain types: `pip install sagashield[langchain]`.
- From source: `maturin develop --features python` (see `CONTRIBUTING.md`).

## 2. Standalone binaries (.exe / .tar.gz) from GitHub Releases

Every `v*` tag builds, via `.github/workflows/release-binaries.yml`:

| Asset | Platform |
|---|---|
| `sagashield-vX.Y.Z-windows-x64.zip` | Windows x64 (`sagashield-mcp.exe` + README + LICENSE) |
| `sagashield-vX.Y.Z-linux-x64.tar.gz` | Linux x64 |
| `sagashield-vX.Y.Z-darwin-arm64.tar.gz` | macOS Apple Silicon |
| `sagashield-vX.Y.Z-darwin-x64.tar.gz` | macOS Intel |
| `SHA256SUMS.txt` | Checksums for all of the above |

Unzip/untar anywhere and run the binary — no runtime dependencies besides
the OS C library. Local equivalent: `scripts/package_local.bat` (Windows)
or `scripts/package_local.sh` (Linux/macOS), producing `dist/`.

## 3. MCP clients: Claude Desktop / Cursor / Claude Code CLI

The binary speaks JSON-RPC 2.0 over stdio (`protocolVersion 2024-11-05`).

**Claude Code CLI (one command):**

```bash
claude mcp add sagashield -- /path/to/sagashield-mcp
```

Run it from the directory that should host `./workspace` (sandbox) and
`./sagashield-mcp.db` (WAL). Ready-made configs live in `integrations/`:

- `integrations/claude_code.md` — exact CLI commands per scope/OS.
- `integrations/cursor.json` — paste into Cursor MCP settings.
- `integrations/claude_desktop.json` — Claude Desktop config
  (see also `claude_desktop_config.example.json`).
- `.claude-plugin/marketplace.json` — `/plugin marketplace add`.

## 4. Docker container

```bash
docker build -t sagashield-mcp:0.3.0 .
docker run -i --rm -v sagashield-data:/data sagashield-mcp:0.3.0
```

- Multi-stage build (`Dockerfile`): `rust:1.80-slim` builder with stripped
  symbols, `distroless/cc-debian12` runtime — final image target < 30 MB.
- Runs as non-root uid `65532`; persist sagas by mounting `/data`
  (WAL + `./workspace` live there).
- Attach the container's stdin/stdout to your MCP client for stdio transport.

## 5. Verifying download integrity

```bash
# Windows (PowerShell)
$h = (Get-FileHash sagashield-vX.Y.Z-windows-x64.zip -Algorithm SHA256).Hash.ToLower()
Select-String -Path SHA256SUMS.txt -Pattern $h

# Linux / macOS
sha256sum -c SHA256SUMS.txt
```

Compare against the `SHA256SUMS.txt` published on the same GitHub Release
page. Mismatches mean a corrupt or tampered download — do not run it.
