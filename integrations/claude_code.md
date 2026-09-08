# sagashield in Claude Code CLI — guida rapida

Prerequisito: `cargo build --release` (produce `target/release/sagashield-mcp`).

## Registrazione one-shot (stdio, scope user)

```bash
claude mcp add sagashield --cwd C:\agent-kernel -- C:\agent-kernel\target\release\sagashield-mcp.exe
```

Varianti:

```bash
# Solo per il progetto corrente
claude mcp add sagashield --scope project --cwd C:\agent-kernel -- C:\agent-kernel\target\release\sagashield-mcp.exe

# macOS / Linux
claude mcp add sagashield --cwd /path/to/sagashield -- /path/to/sagashield/target/release/sagashield-mcp
```

## Verifica

```bash
claude mcp list        # sagashield deve comparire come connected
claude mcp get sagashield
```

Poi in sessione: chiedi all'agente di usare `fs_write` (scrittura sandboxata con
rollback), `mock_pay`, `kernel_status` o il gateway universale
`agent_kernel_exec` (`{ "tool_name": "fs_write", "parameters": {...} }`).

## Note operative

- Il server crea `./workspace` (sandbox) e `./sagashield-mcp.db` (WAL) nella
  working directory da cui viene lanciato: lancialo dalla root del repo.
- stdout è protocollo puro (i log vanno su stderr): non avvolgere il comando
  in pipe che alterino stdout.
- Rimuovi con `claude mcp remove sagashield`.
