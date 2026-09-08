//! Policy di sandboxing — Fase 4.
//!
//! Difende da prompt injection / comportamenti malevoli:
//! path traversal (`..`), file sensibili (`.env`, chiavi), domini non autorizzati.

use std::path::{Component, Path, PathBuf};

use crate::error::{KernelError, KernelResult};

/// Guardrail di sicurezza (object-safe: usabile come `Arc<dyn SecurityGuard>`).
pub trait SecurityGuard: Send + Sync + 'static {
    /// Valida un path e ritorna il path assoluto normalizzato.
    ///
    /// Fallisce con `PathTraversalDetected` (fuori sandbox),
    /// `BlockedFileAccess` (pattern vietato) o `SecurityViolation`
    /// (path vuoto / CWD irresolvibile).
    fn check_path_access(&self, target_path: &Path) -> KernelResult<PathBuf>;

    /// Valida un dominio o URL contro la whitelist.
    ///
    /// Fallisce con `UnauthorizedNetworkAccess` (o `SecurityViolation` se vuoto).
    fn check_network_access(&self, domain_or_url: &str) -> KernelResult<()>;
}

/// Policy whitelist-based del sandbox.
#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    /// Directory in cui l'agente può leggere/scrivere (confronto su path normalizzato).
    pub allowed_root_paths: Vec<PathBuf>,
    /// Pattern vietati (match case-insensitive su ogni componente del path).
    pub blocked_file_patterns: Vec<String>,
    /// Domini autorizzati (match esatto o sottodominio, case-insensitive).
    pub allowed_network_domains: Vec<String>,
}

impl SecurityPolicy {
    /// Crea una policy esplicita (liste già normalizzate dal chiamante se serve).
    pub fn new(
        allowed_root_paths: Vec<PathBuf>,
        blocked_file_patterns: Vec<String>,
        allowed_network_domains: Vec<String>,
    ) -> Self {
        Self {
            allowed_root_paths,
            blocked_file_patterns,
            allowed_network_domains,
        }
    }

    /// Roots come path assoluti normalizzati (lexical, senza toccare il FS).
    fn normalized_roots(&self) -> KernelResult<Vec<PathBuf>> {
        let mut out = Vec::with_capacity(self.allowed_root_paths.len());
        for r in &self.allowed_root_paths {
            out.push(to_absolute_normalized(r)?);
        }
        Ok(out)
    }
}

impl SecurityGuard for SecurityPolicy {
    fn check_path_access(&self, target_path: &Path) -> KernelResult<PathBuf> {
        if target_path.as_os_str().is_empty() {
            return Err(KernelError::SecurityViolation("empty path".to_owned()));
        }

        let normalized = to_absolute_normalized(target_path)?;
        let roots = self.normalized_roots()?;

        // 1. Deve ricadere rigorosamente in una root (anti `..` / assoluti esterni).
        let inside = roots.iter().any(|r| normalized.starts_with(r));
        if !inside {
            // Risoluzione symlink best-effort se il file (o il parent) esiste:
            // un symlink che punta fuori sandbox è comunque traversal.
            return Err(KernelError::PathTraversalDetected(format!(
                "path '{}' escapes allowed roots {:?}",
                normalized.display(),
                roots
            )));
        }
        if let Some(canonical) = canonical_if_exists(&normalized) {
            let canonical_roots: Vec<PathBuf> = roots
                .iter()
                .map(|r| canonical_if_exists(r).unwrap_or_else(|| r.clone()))
                .collect();
            let still_inside = canonical_roots.iter().any(|r| canonical.starts_with(r));
            if !still_inside {
                return Err(KernelError::PathTraversalDetected(format!(
                    "symlink escape: '{}' resolves to '{}'",
                    normalized.display(),
                    canonical.display()
                )));
            }
        }

        // 2. Screening per-componente (case-insensitive, forma normalizzata Win32).
        let components: Vec<Component<'_>> = normalized.components().collect();
        for (index, component) in components.iter().enumerate() {
            let is_last = index + 1 == components.len();
            let raw = component.as_os_str().to_string_lossy().to_lowercase();
            // Win32/NTFS ignora trailing dots e trailing spaces
            // (`foo.txt.` → `foo.txt`, `.env ` → `.env`): giudica la forma
            // normalizzata, non quella letterale.
            let text = raw.trim_end_matches(['.', ' ']);
            if text.is_empty() {
                continue;
            }
            for pattern in &self.blocked_file_patterns {
                let pat = pattern.to_lowercase();
                if !pat.is_empty() && text.contains(&pat) {
                    return Err(KernelError::BlockedFileAccess(format!(
                        "path '{}' matches blocked pattern '{pattern}'",
                        normalized.display()
                    )));
                }
            }
            // 3. Alternate Data Streams (`file.txt:evil`) e backslash fuori
            // posto — solo su nomi reali, mai su prefissi drive (`C:`) o root.
            // Il backslash è separatore su Windows e carattere confusivo
            // altrove: la sandbox impone nomi portabili su ogni piattaforma.
            if matches!(component, Component::Normal(_)) {
                if text.contains(':') {
                    return Err(KernelError::BlockedFileAccess(format!(
                        "path '{}' contains Alternate Data Stream marker ':'",
                        normalized.display()
                    )));
                }
                if text.contains('\\') {
                    return Err(KernelError::BlockedFileAccess(format!(
                        "path '{}' contains backslash (non-portable name)",
                        normalized.display()
                    )));
                }
            }
            // 4. Nomi corti 8.3 (`ENV~1`, `DOCUME~1`): solo sul componente
            // finale. Le directory parent con `~N` (es. `RUNNER~1` nei temp
            // di CI) sono legittime e risolte via canonicalizzazione quando
            // esistono; bloccarle romperebbe path perfettamente validi.
            if is_last && has_shortname_pattern(text) {
                return Err(KernelError::BlockedFileAccess(format!(
                    "path '{}' looks like an 8.3 short filename (tilde pattern)",
                    normalized.display()
                )));
            }
            // 5. Device riservati Windows (CON, PRN, AUX, NUL, COM1-9, LPT1-9):
            // su Windows aprono device di sistema, mai file reali.
            if is_reserved_device_name(text) {
                return Err(KernelError::BlockedFileAccess(format!(
                    "path '{}' targets reserved device name '{text}'",
                    normalized.display()
                )));
            }
        }

        Ok(normalized)
    }

    fn check_network_access(&self, domain_or_url: &str) -> KernelResult<()> {
        let host = extract_host(domain_or_url)?;
        for allowed in &self.allowed_network_domains {
            let allow = allowed.trim().trim_end_matches('.').to_lowercase();
            if allow.is_empty() {
                continue;
            }
            if host == allow || host.ends_with(&format!(".{allow}")) {
                return Ok(());
            }
        }
        // Letterali IP (decimale, ottale `0177...`, esadecimale `0x...`,
        // intero a 32 bit): mai in whitelist per definizione, e le notazioni
        // alternative sono classiche tecniche di spoofing.
        if is_ip_literal(&host) {
            return Err(KernelError::UnauthorizedNetworkAccess(format!(
                "IP literals are never whitelisted: '{host}'"
            )));
        }
        Err(KernelError::UnauthorizedNetworkAccess(format!(
            "domain '{host}' is not in whitelist {:?}",
            self.allowed_network_domains
        )))
    }
}

/// Rende un path assoluto + normalizzato lessicalmente (`.`/`..` risolti, no FS).
fn to_absolute_normalized(p: &Path) -> KernelResult<PathBuf> {
    let absolute = if p.is_absolute() {
        p.to_path_buf()
    } else {
        let cwd = std::env::current_dir()
            .map_err(|e| KernelError::SecurityViolation(format!("cannot resolve cwd: {e}")))?;
        cwd.join(p)
    };
    Ok(lexical_normalize(&absolute))
}

/// Risolve `.` e `..` lessicalmente (preserva prefissi Windows `C:\`).
fn lexical_normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in p.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Canonicalizza solo se il path (o un suo parent) esiste; altrimenti `None`.
fn canonical_if_exists(p: &Path) -> Option<PathBuf> {
    if let Ok(c) = std::fs::canonicalize(p) {
        return Some(c);
    }
    // Prova con il parent (file non ancora creato, es. FsWriteTool).
    let mut current: Option<&Path> = p.parent();
    while let Some(dir) = current {
        if let Ok(canon_dir) = std::fs::canonicalize(dir) {
            if let Ok(suffix) = p.strip_prefix(dir) {
                return Some(canon_dir.join(suffix));
            }
            return Some(canon_dir);
        }
        current = dir.parent();
    }
    None
}

/// Estrae l'host (lowercase) da un dominio nudo o da un URL completo.
fn extract_host(domain_or_url: &str) -> KernelResult<String> {
    let input = domain_or_url.trim();
    if input.is_empty() {
        return Err(KernelError::SecurityViolation(
            "empty domain/url".to_owned(),
        ));
    }
    // Via lo schema (`https://`), poi authority fino a `/`, `?`, `#`.
    let after_scheme = match input.split_once("://") {
        Some((_, rest)) => rest,
        None => input,
    };
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .trim();
    // Via `user@`, poi porta `:port`.
    let host = authority
        .rsplit('@')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .trim()
        .trim_end_matches('.')
        .to_lowercase();
    if host.is_empty() {
        return Err(KernelError::SecurityViolation(format!(
            "cannot extract host from '{domain_or_url}'"
        )));
    }
    Ok(host)
}

/// Pattern 8.3 short filename: `~` seguita da cifra (`ENV~1`, `DOCUME~2`).
///
/// Su NTFS con generazione dei nomi corti abilitata, `ENV~1` può risolvere
/// allo stesso file di un nome bloccato (es. un file contenente `.env`),
/// aggirando una blocklist puramente lessicale. Applicato al solo componente
/// finale: le directory parent con `~N` sono legittime (es. temp di CI).
/// Blocco conservativo, documentato in SECURITY.md come over-blocking noto.
fn has_shortname_pattern(component_lower: &str) -> bool {
    component_lower
        .as_bytes()
        .windows(2)
        .any(|w| w[0] == b'~' && w[1].is_ascii_digit())
}

/// Riconosce i nomi device riservati di Windows (confronto su lowercase).
/// `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`, anche con
/// estensione (`NUL.txt`) o stream ADS (`CON:evil`).
fn is_reserved_device_name(component_lower: &str) -> bool {
    // Stem prima di `.` o `:` (`"nul.txt"` → `"nul"`).
    let stem = component_lower.split(['.', ':']).next().unwrap_or("");
    match stem {
        "con" | "prn" | "aux" | "nul" => true,
        s if s.len() == 4 => {
            let bytes = s.as_bytes();
            (bytes[0] == b'c' && bytes[1] == b'o' && bytes[2] == b'm'
                || bytes[0] == b'l' && bytes[1] == b'p' && bytes[2] == b't')
                && bytes[3].is_ascii_digit()
        }
        _ => false,
    }
}

/// Riconosce IPv4/IPv6 in notazione decimale, ottale, esadecimale o intera.
fn is_ip_literal(host: &str) -> bool {
    if host.contains(':') {
        // Possibile IPv6 (contiene `:` e solo esadecimali/`:`/`.`).
        return host
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.');
    }
    // IPv4: 4 parti numeriche (qualsiasi base) oppure un singolo intero.
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() == 4 && parts.iter().all(|p| !p.is_empty() && is_numeric_literal(p)) {
        return true;
    }
    // Singolo intero a 32 bit (`http://2130706433/`).
    !host.is_empty() && is_numeric_literal(host)
}

/// Numerico in base 10, ottale (`0...`) o esadecimale (`0x...`).
fn is_numeric_literal(s: &str) -> bool {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit())
}
