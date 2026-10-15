#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mcp_discovery.py - Endpoint MCP (Model Context Protocol) kesif ve envanter araci

Amac:
  * Endpoint uzerinde kurulu tum MCP istemci konfigurasyonlarini bulur
    (Claude Desktop, Claude Code, Cursor, Windsurf, VS Code, Cline, Roo, Zed,
     Continue, Codex CLI, Gemini CLI, LM Studio, Amazon Q, Goose, Claude Extensions...)
  * Tanimli MCP sunucularini (stdio / http / sse) cikarir
  * Konfigurasyonlarda gomulu credential / secret / token olup olmadigini tarar
  * Calisan MCP proseslerini ve dinleyen portlari tespit eder
  * Istege bagli olarak sunuculara baglanip yeteneklerini (tools / resources / prompts) envanterler
  * Risk puanlamasi yapip JSON + CSV rapor uretir

Sadece standart kutuphane kullanir (Python 3.8+). psutil varsa proses taramasi icin kullanir.

Kullanim:
  python mcp_discovery.py                       # pasif tarama (config + proses + port)
  python mcp_discovery.py --enumerate           # sunuculara baglanip tools/resources/prompts listeler
  python mcp_discovery.py --scan-projects       # home altinda proje bazli .mcp.json vb. ara (derinlik: --depth)
  python mcp_discovery.py --all-users           # tum kullanici profillerini tara (admin/root gerekir)
  python mcp_discovery.py -o /var/log/mcp_inventory --quiet

UYARI: --enumerate stdio sunuculari icin komutu gercekten calistirir (initialize + list cagrilari).
       Bilinmeyen/guvensiz komutlar icin once pasif modda calistirip inceleyin.
"""

import argparse
import csv
import datetime
import getpass
import glob
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import stat
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional, Tuple

VERSION = "1.0.0"
IS_WIN = platform.system() == "Windows"
IS_MAC = platform.system() == "Darwin"
IS_LINUX = platform.system() == "Linux"

# --------------------------------------------------------------------------- #
# Secret tespit kurallari
# --------------------------------------------------------------------------- #

# Anahtar adi uzerinden suphe (env / header / arg isimleri)
SENSITIVE_KEY_RE = re.compile(
    r"(token|secret|passw(or)?d|passwd|pwd|api[_-]?key|apikey|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|credential|auth|bearer|session|cookie|"
    r"connection[_-]?string|dsn|license[_-]?key|webhook|signing[_-]?key|"
    r"aws_secret|azure_|gcp_|service_account|pat\b|oauth)",
    re.IGNORECASE,
)

# Deger uzerinden bilinen secret formatlari
SECRET_VALUE_PATTERNS = [
    ("OpenAI API key", re.compile(r"\bsk-(proj-)?[A-Za-z0-9_\-]{20,}\b")),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("GitHub token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b")),
    ("GitLab token", re.compile(r"\bglpat-[A-Za-z0-9\-_]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[abpors]-[A-Za-z0-9\-]{10,}\b")),
    ("Slack webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+")),
    ("AWS access key id", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("AWS secret key", re.compile(r"(?i)aws.{0,20}?['\"]?[A-Za-z0-9/+=]{40}['\"]?")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Google OAuth", re.compile(r"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b")),
    ("Azure/MS client secret", re.compile(r"\b[A-Za-z0-9~._\-]{3}8Q~[A-Za-z0-9~._\-]{30,}\b")),
    ("Stripe key", re.compile(r"\b(sk|rk|pk)_(live|test)_[A-Za-z0-9]{20,}\b")),
    ("Twilio", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("SendGrid", re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b")),
    ("Hugging Face", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    ("Notion", re.compile(r"\b(secret_|ntn_)[A-Za-z0-9]{40,}\b")),
    ("Atlassian/Jira token", re.compile(r"\bATATT3[A-Za-z0-9_\-=]{50,}\b")),
    ("Databricks", re.compile(r"\bdapi[0-9a-f]{32}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("Private key block", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("Basic auth in URL", re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^/\s:@]+:[^/\s:@]+@")),
    ("Bearer header", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9_\-\.=]{16,}")),
    ("DB connection string", re.compile(r"(?i)\b(postgres(ql)?|mysql|mongodb(\+srv)?|redis|mssql|amqp|sqlserver)://[^\s'\"]+")),
    ("Generic hex secret (>=32)", re.compile(r"\b[0-9a-fA-F]{32,}\b")),
    ("Generic base64 secret (>=40)", re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")),
]

# ${VAR} / $VAR / %VAR% biçiminde ortam degiskeni referansi -> literal secret degil
ENV_REF_RE = re.compile(r"^\s*(\$\{[A-Za-z_][A-Za-z0-9_]*(:-.*)?\}|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%)\s*$")

# Dosya yolu gibi gorunen degerler (key dosyasi, service account json vb.)
KEYFILE_RE = re.compile(r"(?i)\.(pem|key|p12|pfx|jks|json)$|id_(rsa|ed25519|ecdsa)|service[_-]?account|credentials")

# Riskli / yuksek yetkili arac isimleri (enumerate sonucu icin)
DANGEROUS_TOOL_RE = re.compile(
    r"(?i)(exec|execute|run[_-]?command|shell|bash|powershell|cmd|terminal|"
    r"write[_-]?file|delete|remove|rm\b|unlink|drop|truncate|"
    r"send[_-]?(mail|email|message)|transfer|payment|deploy|sudo|chmod|chown|"
    r"eval|spawn|subprocess|kill|format|wipe|git[_-]?push|force)"
)

# Riskli calistirma komutlari (stdio)
RISKY_COMMAND_RE = re.compile(r"(?i)\b(npx|uvx|pipx|bunx|dnx|docker|sh|bash|cmd(\.exe)?|powershell(\.exe)?|pwsh)\b")

# Yerel olmayan URL
LOCAL_HOST_RE = re.compile(r"^(https?|wss?)://(localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)(:\d+)?(/|$)", re.IGNORECASE)

# --------------------------------------------------------------------------- #
# Yardimcilar
# --------------------------------------------------------------------------- #

def log(msg: str, quiet: bool = False):
    if not quiet:
        print(msg, file=sys.stderr, flush=True)


def mask(value: str, keep: int = 4) -> str:
    """Secret degerini maskele; raporda tam deger asla yazilmaz."""
    if value is None:
        return ""
    s = str(value)
    if len(s) <= keep * 2:
        return "*" * len(s)
    return s[:keep] + "*" * min(len(s) - keep * 2, 16) + s[-keep:]


def sha256_short(value: str) -> str:
    return hashlib.sha256(str(value).encode("utf-8", "ignore")).hexdigest()[:16]


def safe_read(path: str, max_bytes: int = 5_000_000) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(max_bytes)
    except Exception:
        return None


def parse_json_lenient(text: str) -> Optional[Any]:
    """JSONC (yorumlu JSON) ve trailing comma toleransli parse."""
    if text is None:
        return None
    try:
        return json.loads(text)
    except Exception:
        pass
    # Yorumlari ve trailing comma'lari temizle
    cleaned = re.sub(r"(?m)^\s*//.*$", "", text)
    cleaned = re.sub(r"/\*.*?\*/", "", cleaned, flags=re.S)
    cleaned = re.sub(r",\s*([}\]])", r"\1", cleaned)
    try:
        return json.loads(cleaned)
    except Exception:
        return None


def parse_toml(text: str) -> Optional[Any]:
    try:
        import tomllib  # py3.11+
        return tomllib.loads(text)
    except Exception:
        try:
            import tomli  # type: ignore
            return tomli.loads(text)
        except Exception:
            return None


def parse_yaml_naive(text: str) -> Optional[Any]:
    """PyYAML varsa kullan, yoksa None (dosya 'bulundu' olarak raporlanir)."""
    try:
        import yaml  # type: ignore
        return yaml.safe_load(text)
    except Exception:
        return None


def file_perms(path: str) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    try:
        st = os.stat(path)
        info["size"] = st.st_size
        info["mtime"] = datetime.datetime.fromtimestamp(st.st_mtime).isoformat()
        if not IS_WIN:
            mode = stat.S_IMODE(st.st_mode)
            info["mode"] = oct(mode)
            info["world_readable"] = bool(mode & stat.S_IROTH)
            info["group_readable"] = bool(mode & stat.S_IRGRP)
            try:
                import pwd
                info["owner"] = pwd.getpwuid(st.st_uid).pw_name
            except Exception:
                info["owner"] = st.st_uid
        else:
            # icacls ile basit kontrol
            try:
                out = subprocess.run(["icacls", path], capture_output=True, text=True, timeout=5).stdout
                info["acl"] = [l.strip() for l in out.splitlines() if l.strip() and not l.startswith("Successfully")]
                info["world_readable"] = bool(re.search(r"(Everyone|Users|Authenticated Users|BUILTIN\\Users)", out))
            except Exception:
                pass
    except Exception as e:
        info["error"] = str(e)
    return info


def expand(p: str, home: str) -> str:
    p = p.replace("~", home, 1) if p.startswith("~") else p
    return os.path.expandvars(p)


# --------------------------------------------------------------------------- #
# Bilinen MCP istemci konfigurasyon yerleri
# --------------------------------------------------------------------------- #

def known_config_locations(home: str) -> List[Tuple[str, str, str]]:
    """(client_name, path_pattern, format) listesi. glob desteklenir."""
    locs: List[Tuple[str, str, str]] = []

    if IS_WIN:
        appdata = os.environ.get("APPDATA") or os.path.join(home, "AppData", "Roaming")
        localapp = os.environ.get("LOCALAPPDATA") or os.path.join(home, "AppData", "Local")
        # Baska kullanici profili taraniyorsa APPDATA env'i yanlis olur -> home uzerinden kur
        if not appdata.lower().startswith(home.lower()):
            appdata = os.path.join(home, "AppData", "Roaming")
            localapp = os.path.join(home, "AppData", "Local")
        locs += [
            ("Claude Desktop", os.path.join(appdata, "Claude", "claude_desktop_config.json"), "json"),
            ("Claude Desktop Extensions", os.path.join(appdata, "Claude", "Claude Extensions", "*", "manifest.json"), "mcpb"),
            ("Claude Desktop Extensions (settings)", os.path.join(appdata, "Claude", "Claude Extensions Settings", "*.json"), "json"),
            ("VS Code (user mcp.json)", os.path.join(appdata, "Code", "User", "mcp.json"), "vscode"),
            ("VS Code (settings.json)", os.path.join(appdata, "Code", "User", "settings.json"), "vscode-settings"),
            ("VS Code Insiders (mcp.json)", os.path.join(appdata, "Code - Insiders", "User", "mcp.json"), "vscode"),
            ("Cline", os.path.join(appdata, "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"), "json"),
            ("Roo Code", os.path.join(appdata, "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings", "mcp_settings.json"), "json"),
            ("Kilo Code", os.path.join(appdata, "Code", "User", "globalStorage", "kilocode.kilo-code", "settings", "mcp_settings.json"), "json"),
            ("Cursor (global)", os.path.join(home, ".cursor", "mcp.json"), "json"),
            ("Windsurf", os.path.join(home, ".codeium", "windsurf", "mcp_config.json"), "json"),
            ("Zed", os.path.join(appdata, "Zed", "settings.json"), "zed"),
            ("Continue", os.path.join(home, ".continue", "config.json"), "continue"),
            ("Continue (yaml)", os.path.join(home, ".continue", "config.yaml"), "yaml"),
            ("Codex CLI", os.path.join(home, ".codex", "config.toml"), "codex"),
            ("Gemini CLI", os.path.join(home, ".gemini", "settings.json"), "json"),
            ("LM Studio", os.path.join(home, ".lmstudio", "mcp.json"), "json"),
            ("Amazon Q", os.path.join(home, ".aws", "amazonq", "mcp.json"), "json"),
            ("Goose", os.path.join(appdata, "Block", "goose", "config", "config.yaml"), "yaml"),
            ("Warp", os.path.join(localapp, "warp", "Warp", "data", "mcp.json"), "json"),
            ("JetBrains (AI Assistant)", os.path.join(appdata, "JetBrains", "*", "options", "mcp*.xml"), "raw"),
            ("Claude Code (global)", os.path.join(home, ".claude.json"), "claude-code"),
            ("Claude Code (settings)", os.path.join(home, ".claude", "settings.json"), "json"),
            ("Claude Code (settings local)", os.path.join(home, ".claude", "settings.local.json"), "json"),
            ("Copilot CLI", os.path.join(home, ".copilot", "mcp-config.json"), "json"),
            ("OpenCode", os.path.join(home, ".config", "opencode", "opencode.json"), "opencode"),
            ("5ire", os.path.join(appdata, "5ire", "mcp.json"), "json"),
            ("Witsy", os.path.join(appdata, "Witsy", "settings.json"), "raw"),
            ("ChatGPT Desktop", os.path.join(localapp, "Packages", "OpenAI.ChatGPT*", "LocalState", "*mcp*"), "raw"),
        ]
    else:
        if IS_MAC:
            app_support = os.path.join(home, "Library", "Application Support")
            locs += [
                ("Claude Desktop", os.path.join(app_support, "Claude", "claude_desktop_config.json"), "json"),
                ("Claude Desktop Extensions", os.path.join(app_support, "Claude", "Claude Extensions", "*", "manifest.json"), "mcpb"),
                ("Claude Desktop Extensions (settings)", os.path.join(app_support, "Claude", "Claude Extensions Settings", "*.json"), "json"),
                ("VS Code (user mcp.json)", os.path.join(app_support, "Code", "User", "mcp.json"), "vscode"),
                ("VS Code (settings.json)", os.path.join(app_support, "Code", "User", "settings.json"), "vscode-settings"),
                ("VS Code Insiders (mcp.json)", os.path.join(app_support, "Code - Insiders", "User", "mcp.json"), "vscode"),
                ("Cline", os.path.join(app_support, "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"), "json"),
                ("Roo Code", os.path.join(app_support, "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings", "mcp_settings.json"), "json"),
                ("Kilo Code", os.path.join(app_support, "Code", "User", "globalStorage", "kilocode.kilo-code", "settings", "mcp_settings.json"), "json"),
                ("Zed", os.path.join(home, ".config", "zed", "settings.json"), "zed"),
                ("Goose", os.path.join(home, ".config", "goose", "config.yaml"), "yaml"),
                ("Warp", os.path.join(home, ".warp", "mcp.json"), "json"),
                ("JetBrains (AI Assistant)", os.path.join(app_support, "JetBrains", "*", "options", "mcp*.xml"), "raw"),
                ("5ire", os.path.join(app_support, "5ire", "mcp.json"), "json"),
                ("ChatGPT Desktop", os.path.join(app_support, "com.openai.chat", "*mcp*"), "raw"),
                ("Raycast", os.path.join(app_support, "com.raycast.macos", "*mcp*"), "raw"),
            ]
        else:  # Linux
            cfg = os.environ.get("XDG_CONFIG_HOME") or os.path.join(home, ".config")
            if not cfg.startswith(home):
                cfg = os.path.join(home, ".config")
            locs += [
                ("Claude Desktop", os.path.join(cfg, "Claude", "claude_desktop_config.json"), "json"),
                ("Claude Desktop Extensions", os.path.join(cfg, "Claude", "Claude Extensions", "*", "manifest.json"), "mcpb"),
                ("VS Code (user mcp.json)", os.path.join(cfg, "Code", "User", "mcp.json"), "vscode"),
                ("VS Code (settings.json)", os.path.join(cfg, "Code", "User", "settings.json"), "vscode-settings"),
                ("VS Code Insiders (mcp.json)", os.path.join(cfg, "Code - Insiders", "User", "mcp.json"), "vscode"),
                ("Cline", os.path.join(cfg, "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"), "json"),
                ("Roo Code", os.path.join(cfg, "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings", "mcp_settings.json"), "json"),
                ("Kilo Code", os.path.join(cfg, "Code", "User", "globalStorage", "kilocode.kilo-code", "settings", "mcp_settings.json"), "json"),
                ("Zed", os.path.join(cfg, "zed", "settings.json"), "zed"),
                ("Goose", os.path.join(cfg, "goose", "config.yaml"), "yaml"),
                ("Warp", os.path.join(home, ".warp", "mcp.json"), "json"),
                ("JetBrains (AI Assistant)", os.path.join(cfg, "JetBrains", "*", "options", "mcp*.xml"), "raw"),
                ("5ire", os.path.join(cfg, "5ire", "mcp.json"), "json"),
            ]
        # Unix ortak
        locs += [
            ("Cursor (global)", os.path.join(home, ".cursor", "mcp.json"), "json"),
            ("Windsurf", os.path.join(home, ".codeium", "windsurf", "mcp_config.json"), "json"),
            ("Continue", os.path.join(home, ".continue", "config.json"), "continue"),
            ("Continue (yaml)", os.path.join(home, ".continue", "config.yaml"), "yaml"),
            ("Codex CLI", os.path.join(home, ".codex", "config.toml"), "codex"),
            ("Gemini CLI", os.path.join(home, ".gemini", "settings.json"), "json"),
            ("LM Studio", os.path.join(home, ".lmstudio", "mcp.json"), "json"),
            ("Amazon Q", os.path.join(home, ".aws", "amazonq", "mcp.json"), "json"),
            ("Claude Code (global)", os.path.join(home, ".claude.json"), "claude-code"),
            ("Claude Code (settings)", os.path.join(home, ".claude", "settings.json"), "json"),
            ("Claude Code (settings local)", os.path.join(home, ".claude", "settings.local.json"), "json"),
            ("Copilot CLI", os.path.join(home, ".copilot", "mcp-config.json"), "json"),
            ("OpenCode", os.path.join(home, ".config", "opencode", "opencode.json"), "opencode"),
            ("Aider", os.path.join(home, ".aider.conf.yml"), "yaml"),
            ("mcp-cli / generic", os.path.join(home, ".mcp.json"), "json"),
            ("Claude Code (~/.mcp.json)", os.path.join(home, ".mcp.json"), "json"),
        ]
    return locs


# Proje dizinlerinde aranacak dosya adlari (--scan-projects)
PROJECT_CONFIG_NAMES = [
    (".mcp.json", "json", "Claude Code (proje)"),
    (os.path.join(".cursor", "mcp.json"), "json", "Cursor (proje)"),
    (os.path.join(".vscode", "mcp.json"), "vscode", "VS Code (proje)"),
    (os.path.join(".claude", "settings.json"), "json", "Claude Code (proje settings)"),
    (os.path.join(".claude", "settings.local.json"), "json", "Claude Code (proje settings local)"),
    (os.path.join(".windsurf", "mcp.json"), "json", "Windsurf (proje)"),
    (os.path.join(".gemini", "settings.json"), "json", "Gemini CLI (proje)"),
    (os.path.join(".codex", "config.toml"), "codex", "Codex CLI (proje)"),
    (os.path.join(".roo", "mcp.json"), "json", "Roo Code (proje)"),
    (os.path.join(".kiro", "settings", "mcp.json"), "json", "Kiro (proje)"),
    (os.path.join(".amazonq", "mcp.json"), "json", "Amazon Q (proje)"),
    ("mcp.json", "json", "Generic mcp.json"),
    ("mcp_config.json", "json", "Generic mcp_config.json"),
]

SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "__pycache__", ".cache", "Library", "AppData",
             ".npm", ".cargo", ".rustup", "site-packages", "dist", "build", ".Trash", "$RECYCLE.BIN"}


# --------------------------------------------------------------------------- #
# Konfigurasyon parse: her formattan ortak server modeline
# --------------------------------------------------------------------------- #

def normalize_server(name: str, raw: Any, client: str, source: str, scope: str = "user") -> Optional[Dict[str, Any]]:
    if not isinstance(raw, dict):
        return None
    cmd = raw.get("command")
    args = raw.get("args") or []
    url = raw.get("url") or raw.get("serverUrl") or raw.get("endpoint") or raw.get("httpUrl")
    transport = raw.get("type") or raw.get("transport") or raw.get("transportType")
    if not transport:
        if url:
            transport = "sse" if str(url).rstrip("/").endswith("/sse") else "http"
        elif cmd:
            transport = "stdio"
        else:
            transport = "unknown"
    env = raw.get("env") or raw.get("environment") or {}
    headers = raw.get("headers") or raw.get("requestInit", {}).get("headers", {}) if isinstance(raw.get("requestInit"), dict) else raw.get("headers") or {}
    disabled = bool(raw.get("disabled") or raw.get("enabled") is False)
    if isinstance(args, str):
        args = args.split()
    # Codex: command + args; VS Code: inputs ile ${input:...}
    return {
        "name": str(name),
        "client": client,
        "source_file": source,
        "scope": scope,
        "transport": str(transport).lower(),
        "command": cmd,
        "args": [str(a) for a in args] if isinstance(args, list) else [],
        "url": url,
        "env": env if isinstance(env, dict) else {},
        "headers": headers if isinstance(headers, dict) else {},
        "cwd": raw.get("cwd"),
        "disabled": disabled,
        "always_allow": raw.get("alwaysAllow") or raw.get("autoApprove") or raw.get("trust"),
        "raw_keys": sorted(list(raw.keys())),
    }


def extract_servers_from_dict(data: Any, client: str, source: str, fmt: str) -> List[Dict[str, Any]]:
    servers: List[Dict[str, Any]] = []
    if not isinstance(data, dict):
        return servers

    def add_map(m: Any, scope: str = "user"):
        if isinstance(m, dict):
            for n, r in m.items():
                s = normalize_server(n, r, client, source, scope)
                if s:
                    servers.append(s)
        elif isinstance(m, list):  # Continue: liste formati
            for r in m:
                if isinstance(r, dict):
                    s = normalize_server(r.get("name") or r.get("id") or "unnamed", r, client, source, scope)
                    if s:
                        servers.append(s)

    if fmt in ("json", "vscode", "claude-code", "opencode", "continue", "codex", "yaml", "zed", "vscode-settings"):
        # Genel anahtarlar
        for key in ("mcpServers", "mcp_servers", "servers", "mcp", "context_servers", "mcpServerConfigs"):
            v = data.get(key)
            if key == "mcp" and isinstance(v, dict) and "servers" in v:
                add_map(v.get("servers"))
            elif key == "mcp" and isinstance(v, dict) and not any(isinstance(x, dict) and ("command" in x or "url" in x) for x in v.values()):
                continue
            else:
                add_map(v)
        # Continue: experimental.modelContextProtocolServers
        exp = data.get("experimental")
        if isinstance(exp, dict):
            add_map(exp.get("modelContextProtocolServers"))
        # Claude Code: projects.<path>.mcpServers
        projects = data.get("projects")
        if isinstance(projects, dict):
            for ppath, pconf in projects.items():
                if isinstance(pconf, dict) and isinstance(pconf.get("mcpServers"), dict):
                    for n, r in pconf["mcpServers"].items():
                        s = normalize_server(n, r, client, source, scope="project:" + str(ppath))
                        if s:
                            servers.append(s)
        # Claude Code settings: enabledMcpjsonServers / disabledMcpjsonServers
        # Gemini: mcpServers (zaten)
    if fmt == "mcpb":
        # Claude Desktop extension manifest (.mcpb / .dxt)
        srv = data.get("server")
        if isinstance(srv, dict):
            mc = srv.get("mcp_config") or {}
            s = normalize_server(data.get("name") or "extension", mc, client, source, "extension")
            if s:
                s["extension_meta"] = {
                    "display_name": data.get("display_name"),
                    "version": data.get("version"),
                    "author": (data.get("author") or {}).get("name") if isinstance(data.get("author"), dict) else data.get("author"),
                    "user_config_keys": list((data.get("user_config") or {}).keys()),
                    "tools": [t.get("name") for t in data.get("tools") or [] if isinstance(t, dict)],
                }
                servers.append(s)
    return servers


def parse_config_file(path: str, client: str, fmt: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Dosyayi parse et; (servers, file_record) dondur."""
    rec: Dict[str, Any] = {"path": path, "client": client, "format": fmt, "parsed": False}
    rec.update(file_perms(path))
    text = safe_read(path)
    if text is None:
        rec["error"] = "okunamadi"
        return [], rec
    rec["sha256"] = hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest()

    data = None
    if fmt in ("json", "vscode", "vscode-settings", "claude-code", "opencode", "continue", "zed", "mcpb"):
        data = parse_json_lenient(text)
    elif fmt == "codex":
        data = parse_toml(text)
    elif fmt == "yaml":
        data = parse_yaml_naive(text)
        if data is None:
            rec["note"] = "PyYAML yok veya parse edilemedi; ham metin secret taramasi yapildi"
    elif fmt == "raw":
        rec["note"] = "Yapisal parse yok; ham metin secret taramasi yapildi"

    servers: List[Dict[str, Any]] = []
    if data is not None:
        rec["parsed"] = True
        servers = extract_servers_from_dict(data, client, path, fmt)

    # Ham metin ustunde de secret tara (parse edilemese bile yakala)
    rec["raw_text_findings"] = scan_text_for_secrets(text, context=path)
    return servers, rec


# --------------------------------------------------------------------------- #
# Secret tarama
# --------------------------------------------------------------------------- #

def classify_value(key: str, value: Any) -> List[Dict[str, Any]]:
    """Tek bir key/value cifti icin bulgular."""
    findings: List[Dict[str, Any]] = []
    if value is None:
        return findings
    sval = str(value)
    key_s = str(key)

    if ENV_REF_RE.match(sval):
        if SENSITIVE_KEY_RE.search(key_s):
            findings.append({"type": "env_reference", "key": key_s, "value_masked": sval, "severity": "info",
                             "detail": "Hassas anahtar ortam degiskenine referans veriyor (literal degil)"})
        return findings
    if re.match(r"^\$\{input:", sval):  # VS Code inputs
        return findings

    if SENSITIVE_KEY_RE.search(key_s) and sval.strip() and len(sval) >= 6:
        findings.append({"type": "literal_secret_by_key", "key": key_s, "value_masked": mask(sval),
                         "value_hash": sha256_short(sval), "severity": "high",
                         "detail": "Hassas isimli anahtar literal deger iceriyor"})
    for label, rx in SECRET_VALUE_PATTERNS:
        if rx.search(sval):
            sev = "high"
            if label.startswith("Generic"):
                # generic desenler sadece hassas key ile birlikte anlamli
                if not SENSITIVE_KEY_RE.search(key_s):
                    continue
                sev = "medium"
            findings.append({"type": "literal_secret_by_pattern", "pattern": label, "key": key_s,
                             "value_masked": mask(sval), "value_hash": sha256_short(sval), "severity": sev})
    if KEYFILE_RE.search(sval) and (os.path.sep in sval or "/" in sval):
        findings.append({"type": "keyfile_path", "key": key_s, "value_masked": sval, "severity": "medium",
                         "detail": "Anahtar/credential dosyasina yol veriliyor", "exists": os.path.exists(expand(sval, os.path.expanduser("~")))})
    return findings


def scan_text_for_secrets(text: str, context: str = "") -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen = set()
    for label, rx in SECRET_VALUE_PATTERNS:
        if label.startswith("Generic"):
            continue
        for m in rx.finditer(text):
            v = m.group(0)
            h = sha256_short(v)
            if (label, h) in seen:
                continue
            seen.add((label, h))
            out.append({"type": "raw_text_pattern", "pattern": label, "value_masked": mask(v), "value_hash": h, "severity": "high"})
    return out


def scan_server_for_secrets(server: Dict[str, Any]) -> List[Dict[str, Any]]:
    f: List[Dict[str, Any]] = []
    for k, v in (server.get("env") or {}).items():
        for x in classify_value(k, v):
            x["location"] = "env"
            f.append(x)
    for k, v in (server.get("headers") or {}).items():
        for x in classify_value(k, v):
            x["location"] = "headers"
            f.append(x)
    # args: --token abc, --api-key=xyz, veya ciplak token
    args = server.get("args") or []
    for i, a in enumerate(args):
        if "=" in a and a.startswith("-"):
            k, _, v = a.partition("=")
            for x in classify_value(k, v):
                x["location"] = "args[%d]" % i
                f.append(x)
        elif a.startswith("-") and i + 1 < len(args) and SENSITIVE_KEY_RE.search(a):
            for x in classify_value(a, args[i + 1]):
                x["location"] = "args[%d]" % (i + 1)
                f.append(x)
        else:
            for label, rx in SECRET_VALUE_PATTERNS:
                if label.startswith("Generic"):
                    continue
                if rx.search(a):
                    f.append({"type": "literal_secret_by_pattern", "pattern": label, "key": "arg", "location": "args[%d]" % i,
                              "value_masked": mask(a), "value_hash": sha256_short(a), "severity": "high"})
    # URL icinde credential / token query
    url = server.get("url")
    if url:
        for label, rx in SECRET_VALUE_PATTERNS:
            if label.startswith("Generic"):
                continue
            if rx.search(str(url)):
                f.append({"type": "secret_in_url", "pattern": label, "location": "url", "value_masked": mask(str(url), 12), "severity": "high"})
        if re.search(r"(?i)[?&](token|key|api[_-]?key|auth|access_token|sig)=", str(url)):
            f.append({"type": "secret_in_url", "pattern": "query-string credential", "location": "url",
                      "value_masked": mask(str(url), 12), "severity": "high"})
    # Ayni deger icin tekrar eden bulgulari birlestir (en yuksek severity kalir, desenler toplanir)
    merged: Dict[Tuple[str, str], Dict[str, Any]] = {}
    order = {"high": 3, "medium": 2, "info": 1}
    for x in f:
        k = (x.get("location", ""), x.get("value_hash") or x.get("value_masked", ""))
        if k in merged:
            m = merged[k]
            if order.get(x["severity"], 0) > order.get(m["severity"], 0):
                m["severity"] = x["severity"]
            if x.get("pattern") and x["pattern"] not in m.setdefault("patterns", []):
                m["patterns"].append(x["pattern"])
        else:
            x = dict(x)
            if x.get("pattern"):
                x["patterns"] = [x.pop("pattern")]
            merged[k] = x
    return list(merged.values())


# --------------------------------------------------------------------------- #
# Risk degerlendirme
# --------------------------------------------------------------------------- #

def assess_server(server: Dict[str, Any]) -> Dict[str, Any]:
    risks: List[Dict[str, str]] = []
    score = 0

    secrets = server.get("secret_findings") or []
    high = [s for s in secrets if s.get("severity") == "high"]
    med = [s for s in secrets if s.get("severity") == "medium"]
    if high:
        score += 40 + 5 * (len(high) - 1)
        risks.append({"id": "CRED_LITERAL", "severity": "high", "msg": "%d adet literal credential/secret konfigurasyonda gomulu" % len(high)})
    if med:
        score += 15
        risks.append({"id": "CRED_POSSIBLE", "severity": "medium", "msg": "%d adet olasi secret / anahtar dosyasi referansi" % len(med)})

    url = server.get("url")
    if url:
        u = str(url)
        if not LOCAL_HOST_RE.match(u):
            score += 20
            risks.append({"id": "REMOTE_SERVER", "severity": "medium", "msg": "Uzak MCP sunucusu: %s (veri sizintisi / tedarik zinciri riski)" % u})
        if u.lower().startswith("http://") and not LOCAL_HOST_RE.match(u):
            score += 15
            risks.append({"id": "PLAINTEXT_HTTP", "severity": "high", "msg": "Sifrelenmemis HTTP uzerinden uzak MCP"})
        if server.get("transport") == "sse":
            risks.append({"id": "SSE_DEPRECATED", "severity": "low", "msg": "Eski SSE transport; Streamable HTTP'ye gecis onerilir"})

    cmd = server.get("command")
    args = server.get("args") or []
    full = " ".join([str(cmd or "")] + args)
    if cmd:
        if RISKY_COMMAND_RE.search(str(cmd)):
            if re.search(r"(?i)\b(npx|uvx|pipx|bunx|dnx)\b", str(cmd)):
                score += 15
                risks.append({"id": "EPHEMERAL_PKG_EXEC", "severity": "medium",
                              "msg": "Paket her calismada registry'den cekiliyor (%s) - versiyon sabitlenmemis olabilir / tedarik zinciri" % cmd})
                if not re.search(r"@[0-9]+\.[0-9]+", full) and not re.search(r"==[0-9]", full):
                    score += 5
                    risks.append({"id": "UNPINNED_VERSION", "severity": "low", "msg": "Paket surumu sabitlenmemis"})
            if re.search(r"(?i)\b(sh|bash|cmd(\.exe)?|powershell(\.exe)?|pwsh)\b", str(cmd)):
                score += 20
                risks.append({"id": "SHELL_WRAPPER", "severity": "high", "msg": "MCP sunucusu shell uzerinden calistiriliyor"})
            if "docker" in str(cmd).lower():
                if re.search(r"--privileged|-v\s*/:|/var/run/docker\.sock", full):
                    score += 25
                    risks.append({"id": "DOCKER_PRIVILEGED", "severity": "high", "msg": "Privileged / host-mount docker MCP"})
        # Dosya sistemi / genis erisim
        if re.search(r"(?i)server-filesystem|filesystem", full):
            roots = [a for a in args if os.path.isabs(a)]
            wide = [r for r in roots if r in ("/", "C:\\", "C:/", os.path.expanduser("~"))]
            if wide:
                score += 20
                risks.append({"id": "FS_WIDE_ACCESS", "severity": "high", "msg": "Filesystem MCP kok/home dizinine erisiyor: %s" % wide})
        # Komut gercekten mevcut mu
        exe = shutil.which(str(cmd)) if not os.path.isabs(str(cmd)) else (str(cmd) if os.path.exists(str(cmd)) else None)
        server["command_resolved"] = exe
        if exe is None:
            risks.append({"id": "CMD_NOT_FOUND", "severity": "info", "msg": "Komut PATH'te bulunamadi (bu kullanici baglaminda)"})
        else:
            # Script dosyasi herkes tarafindan yazilabilir mi?
            script_candidates = [exe] + [a for a in args if os.path.isabs(a) and os.path.isfile(a)]
            for sc in script_candidates:
                try:
                    if not IS_WIN and os.stat(sc).st_mode & stat.S_IWOTH:
                        score += 25
                        risks.append({"id": "WORLD_WRITABLE_BINARY", "severity": "high", "msg": "MCP binary/script herkes tarafindan yazilabilir: %s" % sc})
                except Exception:
                    pass

    if server.get("always_allow"):
        score += 10
        risks.append({"id": "AUTO_APPROVE", "severity": "medium", "msg": "Araclar otomatik onayli (alwaysAllow/autoApprove/trust): %s" % str(server["always_allow"])[:120]})

    # Enumerate sonucu
    caps = server.get("capabilities") or {}
    tools = caps.get("tools") or []
    dangerous = [t.get("name") for t in tools if DANGEROUS_TOOL_RE.search(str(t.get("name", "")) + " " + str(t.get("description", ""))[:200])]
    if dangerous:
        score += 15
        risks.append({"id": "DANGEROUS_TOOLS", "severity": "medium", "msg": "Yuksek etkili araclar: %s" % ", ".join(dangerous[:10])})
    # Tool description'da prompt injection / gizli talimat
    inj = [t.get("name") for t in tools if re.search(r"(?i)(ignore (previous|all) instructions|do not tell the user|<important>|hidden|secretly|before (using|calling) this tool.*(read|send|cat)\s)", str(t.get("description", "")))]
    if inj:
        score += 30
        risks.append({"id": "TOOL_POISONING", "severity": "high", "msg": "Tool description'da supheli talimat (tool poisoning): %s" % ", ".join(inj[:10])})

    if server.get("disabled"):
        score = int(score * 0.5)
        risks.append({"id": "DISABLED", "severity": "info", "msg": "Sunucu konfigurasyonda devre disi"})

    level = "critical" if score >= 60 else "high" if score >= 40 else "medium" if score >= 20 else "low"
    return {"score": min(score, 100), "level": level, "risks": risks}


# --------------------------------------------------------------------------- #
# Proses ve port taramasi
# --------------------------------------------------------------------------- #

PROC_KEYWORDS = re.compile(
    r"(?i)(mcp|modelcontextprotocol|mcp-server|mcp_server|server-filesystem|server-github|"
    r"fastmcp|mcp-remote|mcp-proxy|supergateway|@anthropic|claude-desktop|cline|roo-code)"
)


def list_processes() -> List[Dict[str, Any]]:
    procs: List[Dict[str, Any]] = []
    try:
        import psutil  # type: ignore
        for p in psutil.process_iter(["pid", "ppid", "name", "username", "cmdline", "create_time", "cwd"]):
            try:
                cmd = " ".join(p.info.get("cmdline") or [])
                procs.append({"pid": p.info["pid"], "ppid": p.info.get("ppid"), "name": p.info.get("name"),
                              "user": p.info.get("username"), "cmdline": cmd,
                              "started": datetime.datetime.fromtimestamp(p.info["create_time"]).isoformat() if p.info.get("create_time") else None})
            except Exception:
                continue
        return procs
    except ImportError:
        pass
    try:
        if IS_WIN:
            ps = ("Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine | "
                  "ConvertTo-Json -Compress")
            out = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True, timeout=60).stdout
            data = json.loads(out) if out.strip() else []
            if isinstance(data, dict):
                data = [data]
            for d in data:
                procs.append({"pid": d.get("ProcessId"), "ppid": d.get("ParentProcessId"), "name": d.get("Name"),
                              "user": None, "cmdline": d.get("CommandLine") or ""})
        else:
            out = subprocess.run(["ps", "-eo", "pid=,ppid=,user=,args="], capture_output=True, text=True, timeout=30).stdout
            for line in out.splitlines():
                parts = line.strip().split(None, 3)
                if len(parts) >= 4:
                    procs.append({"pid": int(parts[0]), "ppid": int(parts[1]), "user": parts[2], "name": parts[3].split()[0], "cmdline": parts[3]})
    except Exception as e:
        procs.append({"error": str(e)})
    return procs


def find_mcp_processes(all_procs: List[Dict[str, Any]], servers: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    # Config'den bilinen komut/arg parcalari
    known_tokens: List[Tuple[str, str]] = []
    for s in servers:
        if s.get("command"):
            tok = " ".join([str(s["command"])] + (s.get("args") or [])[:2])
            known_tokens.append((s["name"], tok))
    self_pid = os.getpid()
    self_ppid = os.getppid()
    for p in all_procs:
        cmd = p.get("cmdline") or ""
        if not cmd or p.get("pid") in (self_pid, self_ppid):
            continue
        matched_cfg = [n for n, tok in known_tokens if tok and tok in cmd]
        if PROC_KEYWORDS.search(cmd) or matched_cfg:
            h = dict(p)
            h["matched_config_servers"] = matched_cfg
            h["cmdline"] = redact_cmdline(cmd)
            h["secret_findings"] = scan_text_for_secrets(cmd)
            # Komut satirinda --token vb.
            for m in re.finditer(r"(?i)(--?[a-z_\-]*(token|key|secret|pass|auth)[a-z_\-]*)[= ]([^\s]+)", cmd):
                h["secret_findings"].append({"type": "cmdline_credential", "key": m.group(1), "value_masked": mask(m.group(3)), "severity": "high"})
            hits.append(h)
    return hits


def redact_cmdline(cmd: str) -> str:
    cmd = re.sub(r"(?i)(--?[a-z_\-]*(token|key|secret|pass|auth)[a-z_\-]*[= ])([^\s]+)", lambda m: m.group(1) + mask(m.group(3)), cmd)
    for label, rx in SECRET_VALUE_PATTERNS:
        if label.startswith("Generic"):
            continue
        cmd = rx.sub(lambda m: mask(m.group(0)), cmd)
    return cmd


def list_listening_ports() -> List[Dict[str, Any]]:
    ports: List[Dict[str, Any]] = []
    try:
        import psutil  # type: ignore
        for c in psutil.net_connections(kind="inet"):
            if c.status == "LISTEN" and c.laddr:
                try:
                    pname = psutil.Process(c.pid).name() if c.pid else None
                except Exception:
                    pname = None
                ports.append({"addr": c.laddr.ip, "port": c.laddr.port, "pid": c.pid, "process": pname})
        return ports
    except ImportError:
        pass
    try:
        if IS_WIN:
            out = subprocess.run(["netstat", "-ano", "-p", "tcp"], capture_output=True, text=True, timeout=30).stdout
            for line in out.splitlines():
                if "LISTENING" in line:
                    parts = line.split()
                    addr, port = parts[1].rsplit(":", 1)
                    ports.append({"addr": addr, "port": int(port), "pid": int(parts[-1]), "process": None})
        elif shutil.which("ss"):
            out = subprocess.run(["ss", "-ltnp"], capture_output=True, text=True, timeout=30).stdout
            for line in out.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 4:
                    addr, port = parts[3].rsplit(":", 1)
                    m = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
                    ports.append({"addr": addr, "port": int(port), "pid": int(m.group(2)) if m else None, "process": m.group(1) if m else None})
        elif shutil.which("lsof"):
            out = subprocess.run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"], capture_output=True, text=True, timeout=30).stdout
            for line in out.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 9:
                    addr, port = parts[8].rsplit(":", 1)
                    ports.append({"addr": addr, "port": int(port), "pid": int(parts[1]), "process": parts[0]})
        elif shutil.which("netstat"):
            out = subprocess.run(["netstat", "-tlnp"], capture_output=True, text=True, timeout=30).stdout
            for line in out.splitlines():
                if "LISTEN" in line:
                    parts = line.split()
                    addr, port = parts[3].rsplit(":", 1)
                    ports.append({"addr": addr, "port": int(port), "pid": None, "process": parts[-1]})
    except Exception as e:
        ports.append({"error": str(e)})
    return ports


def probe_http_mcp(host: str, port: int, timeout: float = 2.0) -> Optional[Dict[str, Any]]:
    """Bir portta MCP (Streamable HTTP / SSE) olup olmadigini pasife yakin sekilde dene."""
    for scheme in ("http",):
        for path in ("/mcp", "/sse", "/"):
            url = "%s://%s:%d%s" % (scheme, host, port, path)
            try:
                req = urllib.request.Request(url, method="GET", headers={"Accept": "text/event-stream, application/json"})
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    ctype = r.headers.get("Content-Type", "")
                    if "text/event-stream" in ctype:
                        return {"url": url, "evidence": "SSE endpoint", "content_type": ctype}
            except urllib.error.HTTPError as e:
                body = ""
                try:
                    body = e.read(400).decode("utf-8", "ignore")
                except Exception:
                    pass
                if e.code in (405, 406, 400) and ("jsonrpc" in body.lower() or "mcp" in body.lower() or "session" in body.lower()):
                    return {"url": url, "evidence": "HTTP %d with MCP-like body" % e.code}
            except Exception:
                continue
    return None


# --------------------------------------------------------------------------- #
# MCP yetenek envanteri (initialize + tools/resources/prompts list)
# --------------------------------------------------------------------------- #

INIT_PARAMS = {
    "protocolVersion": "2025-06-18",
    "capabilities": {},
    "clientInfo": {"name": "mcp-discovery-audit", "version": VERSION},
}


class StdioMCPClient:
    def __init__(self, command: str, args: List[str], env: Dict[str, str], cwd: Optional[str], timeout: float):
        self.timeout = timeout
        full_env = dict(os.environ)
        for k, v in (env or {}).items():
            full_env[str(k)] = os.path.expandvars(str(v))
        cmd = [command] + list(args)
        if IS_WIN and not os.path.isabs(command):
            resolved = shutil.which(command)
            if resolved:
                cmd[0] = resolved
        self.proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     env=full_env, cwd=cwd or None, text=True, encoding="utf-8", errors="replace",
                                     bufsize=1, shell=False)
        self._id = 0
        self._lines: List[str] = []
        self._lock = threading.Lock()
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _read_loop(self):
        try:
            for line in self.proc.stdout:
                with self._lock:
                    self._lines.append(line)
        except Exception:
            pass

    def _send(self, obj: Dict[str, Any]):
        self.proc.stdin.write(json.dumps(obj) + "\n")
        self.proc.stdin.flush()

    def request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Any:
        self._id += 1
        rid = self._id
        self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            with self._lock:
                pending = list(self._lines)
                self._lines.clear()
            for line in pending:
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except Exception:
                    continue
                if msg.get("id") == rid:
                    if "error" in msg:
                        raise RuntimeError(json.dumps(msg["error"])[:300])
                    return msg.get("result")
            if self.proc.poll() is not None:
                err = ""
                try:
                    err = self.proc.stderr.read(500)
                except Exception:
                    pass
                raise RuntimeError("process exited (rc=%s) %s" % (self.proc.returncode, err.strip()[:300]))
            time.sleep(0.05)
        raise TimeoutError("timeout waiting for %s" % method)

    def notify(self, method: str, params: Optional[Dict[str, Any]] = None):
        self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def close(self):
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.terminate()
            self.proc.wait(timeout=3)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass


class HttpMCPClient:
    """Streamable HTTP (2025-03-26+) istemcisi. SSE-only sunucular icin sinirli destek."""

    def __init__(self, url: str, headers: Dict[str, str], timeout: float):
        self.url = url
        self.timeout = timeout
        self.headers = {str(k): os.path.expandvars(str(v)) for k, v in (headers or {}).items()}
        self.session_id: Optional[str] = None
        self._id = 0

    def _post(self, obj: Dict[str, Any]) -> Tuple[int, Dict[str, str], str]:
        h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        h.update(self.headers)
        if self.session_id:
            h["Mcp-Session-Id"] = self.session_id
        req = urllib.request.Request(self.url, data=json.dumps(obj).encode("utf-8"), headers=h, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = r.read(2_000_000).decode("utf-8", "replace")
                return r.status, dict(r.headers), body
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read(2000).decode("utf-8", "replace")

    @staticmethod
    def _parse_body(body: str, rid: int) -> Any:
        body = body.strip()
        if body.startswith("{") or body.startswith("["):
            msg = json.loads(body)
            msgs = msg if isinstance(msg, list) else [msg]
        else:  # SSE
            msgs = []
            for chunk in body.split("\n\n"):
                for line in chunk.splitlines():
                    if line.startswith("data:"):
                        try:
                            msgs.append(json.loads(line[5:].strip()))
                        except Exception:
                            pass
        for m in msgs:
            if isinstance(m, dict) and m.get("id") == rid:
                if "error" in m:
                    raise RuntimeError(json.dumps(m["error"])[:300])
                return m.get("result")
        raise RuntimeError("no response for id %d" % rid)

    def request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Any:
        self._id += 1
        rid = self._id
        status, hdrs, body = self._post({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})
        if status in (401, 403):
            raise RuntimeError("HTTP %d - kimlik dogrulama gerekli" % status)
        if status >= 400:
            raise RuntimeError("HTTP %d %s" % (status, body[:200]))
        sid = {k.lower(): v for k, v in hdrs.items()}.get("mcp-session-id")
        if sid:
            self.session_id = sid
        return self._parse_body(body, rid)

    def notify(self, method: str, params: Optional[Dict[str, Any]] = None):
        try:
            self._post({"jsonrpc": "2.0", "method": method, "params": params or {}})
        except Exception:
            pass

    def close(self):
        if self.session_id:
            try:
                h = dict(self.headers)
                h["Mcp-Session-Id"] = self.session_id
                req = urllib.request.Request(self.url, headers=h, method="DELETE")
                urllib.request.urlopen(req, timeout=3).close()
            except Exception:
                pass


def enumerate_server(server: Dict[str, Any], timeout: float) -> Dict[str, Any]:
    result: Dict[str, Any] = {"ok": False}
    client = None
    try:
        if server.get("transport") == "stdio" and server.get("command"):
            client = StdioMCPClient(server["command"], server.get("args") or [], server.get("env") or {}, server.get("cwd"), timeout)
        elif server.get("url"):
            if server.get("transport") == "sse" or str(server["url"]).rstrip("/").endswith("/sse"):
                result["error"] = "Eski SSE transport; otomatik envanter desteklenmiyor (Streamable HTTP gerekir)"
                return result
            client = HttpMCPClient(server["url"], server.get("headers") or {}, timeout)
        else:
            result["error"] = "transport belirlenemedi"
            return result

        init = client.request("initialize", INIT_PARAMS)
        client.notify("notifications/initialized")
        result["server_info"] = init.get("serverInfo") if isinstance(init, dict) else None
        result["protocol_version"] = init.get("protocolVersion") if isinstance(init, dict) else None
        result["declared_capabilities"] = init.get("capabilities") if isinstance(init, dict) else None
        result["instructions"] = (init.get("instructions") or "")[:2000] if isinstance(init, dict) else None

        caps = init.get("capabilities", {}) if isinstance(init, dict) else {}

        def collect(method: str, key: str):
            items: List[Any] = []
            cursor = None
            for _ in range(20):
                params = {"cursor": cursor} if cursor else {}
                r = client.request(method, params)
                items.extend(r.get(key, []) if isinstance(r, dict) else [])
                cursor = r.get("nextCursor") if isinstance(r, dict) else None
                if not cursor:
                    break
            return items

        tools = []
        if "tools" in caps or True:  # bazi sunucular capability bildirmez, yine de dene
            try:
                tools = collect("tools/list", "tools")
            except Exception as e:
                result["tools_error"] = str(e)[:200]
        resources, templates, prompts = [], [], []
        if "resources" in caps:
            try:
                resources = collect("resources/list", "resources")
            except Exception as e:
                result["resources_error"] = str(e)[:200]
            try:
                templates = collect("resources/templates/list", "resourceTemplates")
            except Exception:
                pass
        if "prompts" in caps:
            try:
                prompts = collect("prompts/list", "prompts")
            except Exception as e:
                result["prompts_error"] = str(e)[:200]

        result["tools"] = [{"name": t.get("name"), "description": (t.get("description") or "")[:500],
                            "input_schema_keys": list((t.get("inputSchema") or {}).get("properties", {}).keys()),
                            "annotations": t.get("annotations")} for t in tools if isinstance(t, dict)]
        result["resources"] = [{"uri": r.get("uri"), "name": r.get("name"), "mimeType": r.get("mimeType")} for r in resources if isinstance(r, dict)]
        result["resource_templates"] = [{"uriTemplate": r.get("uriTemplate"), "name": r.get("name")} for r in templates if isinstance(r, dict)]
        result["prompts"] = [{"name": p.get("name"), "description": (p.get("description") or "")[:300],
                              "arguments": [a.get("name") for a in p.get("arguments") or []]} for p in prompts if isinstance(p, dict)]
        result["ok"] = True
    except Exception as e:
        result["error"] = str(e)[:400]
    finally:
        if client:
            try:
                client.close()
            except Exception:
                pass
    return result


# --------------------------------------------------------------------------- #
# Kesif ana akisi
# --------------------------------------------------------------------------- #

def discover_homes(all_users: bool) -> List[Tuple[str, str]]:
    homes: List[Tuple[str, str]] = []
    me = os.path.expanduser("~")
    homes.append((getpass.getuser(), me))
    if not all_users:
        return homes
    roots = []
    if IS_WIN:
        roots = [os.path.join(os.environ.get("SystemDrive", "C:"), os.sep, "Users")]
    elif IS_MAC:
        roots = ["/Users"]
    else:
        roots = ["/home", "/root"]
    for r in roots:
        if os.path.isdir(r):
            if r == "/root":
                homes.append(("root", r))
                continue
            for d in os.listdir(r):
                p = os.path.join(r, d)
                if os.path.isdir(p) and p != me and d not in ("Public", "Default", "Default User", "All Users", "Shared"):
                    homes.append((d, p))
    return homes


def scan_projects(home: str, depth: int, quiet: bool) -> List[Tuple[str, str, str]]:
    found: List[Tuple[str, str, str]] = []
    base_depth = home.rstrip(os.sep).count(os.sep)
    for root, dirs, files in os.walk(home):
        cur = root.count(os.sep) - base_depth
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not (d.startswith(".") and d not in (".cursor", ".vscode", ".claude", ".windsurf", ".gemini", ".codex", ".roo", ".kiro", ".amazonq"))]
        if cur >= depth:
            dirs[:] = []
        for rel, fmt, client in PROJECT_CONFIG_NAMES:
            cand = os.path.join(root, rel)
            if os.path.isfile(cand):
                found.append((client, cand, fmt))
    return found


def run(args: argparse.Namespace) -> Dict[str, Any]:
    quiet = args.quiet
    t0 = time.time()
    report: Dict[str, Any] = {
        "tool": "mcp_discovery",
        "version": VERSION,
        "generated_at": datetime.datetime.now().astimezone().isoformat(),
        "host": {
            "hostname": socket.gethostname(),
            "fqdn": socket.getfqdn(),
            "os": platform.platform(),
            "user": getpass.getuser(),
            "python": platform.python_version(),
            "ips": [],
        },
        "options": vars(args),
        "config_files": [],
        "servers": [],
        "processes": [],
        "listening_ports": [],
        "summary": {},
    }
    try:
        report["host"]["ips"] = sorted({ai[4][0] for ai in socket.getaddrinfo(socket.gethostname(), None)})
    except Exception:
        pass

    homes = discover_homes(args.all_users)
    log("[*] Kullanici profilleri: %s" % ", ".join(u for u, _ in homes), quiet)

    servers: List[Dict[str, Any]] = []
    seen_files = set()

    for user, home in homes:
        candidates = list(known_config_locations(home))
        if args.scan_projects:
            log("[*] %s: proje taramasi (derinlik %d)..." % (user, args.depth), quiet)
            candidates += scan_projects(home, args.depth, quiet)
        for client, pattern, fmt in candidates:
            for path in glob.glob(pattern):
                path = os.path.normpath(path)
                if path in seen_files or not os.path.isfile(path):
                    continue
                seen_files.add(path)
                srvs, rec = parse_config_file(path, client, fmt)
                rec["user"] = user
                report["config_files"].append(rec)
                for s in srvs:
                    s["user"] = user
                    s["secret_findings"] = scan_server_for_secrets(s)
                    servers.append(s)
                log("    [+] %-32s %s (%d sunucu)" % (client, path, len(srvs)), quiet)

    log("[*] %d konfigurasyon dosyasi, %d MCP sunucu tanimi bulundu" % (len(report["config_files"]), len(servers)), quiet)

    # Prosesler
    log("[*] Prosesler taraniyor...", quiet)
    all_procs = list_processes()
    report["processes"] = find_mcp_processes(all_procs, servers)
    log("    %d supheli/MCP prosesi" % len(report["processes"]), quiet)

    # Portlar
    log("[*] Dinleyen portlar taraniyor...", quiet)
    ports = list_listening_ports()
    mcp_pids = {p.get("pid") for p in report["processes"] if p.get("pid")}
    for p in ports:
        p["owned_by_mcp_process"] = p.get("pid") in mcp_pids
        p["exposed_externally"] = p.get("addr") in ("0.0.0.0", "::", "*", "[::]")
    if args.probe_ports:
        log("[*] Portlar MCP icin yokleniyor...", quiet)
        for p in ports:
            if "error" in p:
                continue
            if p.get("port", 0) in (0, 22, 53, 135, 139, 445, 3389, 5900):
                continue
            host = "127.0.0.1" if p.get("addr") in ("0.0.0.0", "::", "*", "[::]", "127.0.0.1", "::1") else p.get("addr")
            pr = probe_http_mcp(host, int(p["port"]))
            if pr:
                p["mcp_probe"] = pr
    report["listening_ports"] = [p for p in ports if p.get("owned_by_mcp_process") or p.get("mcp_probe") or "error" in p] if not args.all_ports else ports

    # Envanter
    if args.enumerate:
        log("[*] Sunucu yetenekleri envanterleniyor (timeout %ss)..." % args.timeout, quiet)
        for s in servers:
            if s.get("disabled") and not args.include_disabled:
                s["capabilities"] = {"ok": False, "error": "devre disi; atlandi"}
                continue
            if args.enumerate_filter and not re.search(args.enumerate_filter, s["name"]):
                continue
            log("    -> %s (%s)" % (s["name"], s["transport"]), quiet)
            s["capabilities"] = enumerate_server(s, args.timeout)
            c = s["capabilities"]
            if c.get("ok"):
                log("       tools=%d resources=%d prompts=%d" % (len(c.get("tools", [])), len(c.get("resources", [])), len(c.get("prompts", []))), quiet)
            else:
                log("       hata: %s" % c.get("error"), quiet)

    # Risk
    for s in servers:
        s["assessment"] = assess_server(s)
    report["servers"] = servers

    # Ozet
    by_level: Dict[str, int] = {}
    for s in servers:
        by_level[s["assessment"]["level"]] = by_level.get(s["assessment"]["level"], 0) + 1
    total_secrets = sum(len([f for f in s["secret_findings"] if f.get("severity") == "high"]) for s in servers)
    raw_secrets = sum(len(c.get("raw_text_findings", [])) for c in report["config_files"])
    report["summary"] = {
        "config_files": len(report["config_files"]),
        "servers_total": len(servers),
        "servers_enabled": len([s for s in servers if not s.get("disabled")]),
        "servers_by_transport": _count(servers, "transport"),
        "servers_by_client": _count(servers, "client"),
        "servers_by_risk": by_level,
        "literal_secrets_high": total_secrets,
        "raw_text_secret_hits": raw_secrets,
        "remote_servers": len([s for s in servers if s.get("url") and not LOCAL_HOST_RE.match(str(s["url"]))]),
        "mcp_processes_running": len(report["processes"]),
        "mcp_ports": len([p for p in report["listening_ports"] if "error" not in p]),
        "world_readable_configs": len([c for c in report["config_files"] if c.get("world_readable")]),
        "duration_sec": round(time.time() - t0, 2),
    }
    return report


def _count(items: List[Dict[str, Any]], key: str) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for i in items:
        v = str(i.get(key))
        out[v] = out.get(v, 0) + 1
    return out


# --------------------------------------------------------------------------- #
# Cikti
# --------------------------------------------------------------------------- #

def write_outputs(report: Dict[str, Any], out_dir: str, quiet: bool) -> Tuple[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    host = re.sub(r"[^A-Za-z0-9_\-.]", "_", report["host"]["hostname"])
    jpath = os.path.join(out_dir, "mcp_inventory_%s_%s.json" % (host, stamp))
    cpath = os.path.join(out_dir, "mcp_inventory_%s_%s.csv" % (host, stamp))
    with open(jpath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=str)
    with open(cpath, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["hostname", "user", "client", "server_name", "scope", "transport", "command_or_url", "disabled",
                    "risk_level", "risk_score", "high_secrets", "medium_secrets", "remote", "tools_count", "dangerous_tools",
                    "risks", "source_file"])
        for s in report["servers"]:
            a = s["assessment"]
            caps = s.get("capabilities") or {}
            hs = len([x for x in s["secret_findings"] if x.get("severity") == "high"])
            ms = len([x for x in s["secret_findings"] if x.get("severity") == "medium"])
            dang = next((r["msg"] for r in a["risks"] if r["id"] == "DANGEROUS_TOOLS"), "")
            w.writerow([report["host"]["hostname"], s.get("user"), s["client"], s["name"], s["scope"], s["transport"],
                        s.get("url") or (" ".join([str(s.get("command") or "")] + s.get("args", []))),
                        s.get("disabled"), a["level"], a["score"], hs, ms,
                        bool(s.get("url") and not LOCAL_HOST_RE.match(str(s["url"]))),
                        len(caps.get("tools", [])) if caps.get("ok") else "",
                        dang, " | ".join("%s:%s" % (r["id"], r["severity"]) for r in a["risks"]), s["source_file"]])
    return jpath, cpath


def print_summary(report: Dict[str, Any]):
    s = report["summary"]
    print("\n=== MCP Envanter Ozeti: %s (%s) ===" % (report["host"]["hostname"], report["host"]["user"]))
    print(" Konfig dosyasi      : %d (world-readable: %d)" % (s["config_files"], s["world_readable_configs"]))
    print(" MCP sunucu tanimi   : %d (aktif: %d)  transport=%s" % (s["servers_total"], s["servers_enabled"], s["servers_by_transport"]))
    print(" Istemci dagilimi    : %s" % s["servers_by_client"])
    print(" Risk dagilimi       : %s" % s["servers_by_risk"])
    print(" Literal secret (hi) : %d   ham metin isabeti: %d" % (s["literal_secrets_high"], s["raw_text_secret_hits"]))
    print(" Uzak sunucu         : %d" % s["remote_servers"])
    print(" Calisan MCP prosesi : %d   MCP port: %d" % (s["mcp_processes_running"], s["mcp_ports"]))
    print("")
    for srv in sorted(report["servers"], key=lambda x: -x["assessment"]["score"]):
        a = srv["assessment"]
        target = srv.get("url") or " ".join([str(srv.get("command") or "")] + srv.get("args", [])[:4])
        flag = " [DISABLED]" if srv.get("disabled") else ""
        print(" [%-8s %3d] %-28s %-22s %s%s" % (a["level"].upper(), a["score"], srv["name"][:28], srv["client"][:22], target[:70], flag))
        for r in a["risks"]:
            if r["severity"] in ("high", "medium"):
                print("      - %s: %s" % (r["severity"], r["msg"][:110]))
        for fnd in srv["secret_findings"]:
            if fnd.get("severity") == "high":
                print("      - SECRET %s/%s = %s  (%s)" % (fnd.get("location"), fnd.get("key", "?"), fnd.get("value_masked"),
                                                           ", ".join(fnd.get("patterns") or [fnd.get("type", "")])))
    for p in report["processes"]:
        print(" [PROC %s] %s" % (p.get("pid"), (p.get("cmdline") or "")[:110]))


def post_report(report: Dict[str, Any], url: str, token: Optional[str], quiet: bool):
    try:
        h = {"Content-Type": "application/json"}
        if token:
            h["Authorization"] = "Bearer " + token
        req = urllib.request.Request(url, data=json.dumps(report, default=str).encode("utf-8"), headers=h, method="POST")
        with urllib.request.urlopen(req, timeout=20) as r:
            log("[*] Rapor gonderildi: HTTP %d" % r.status, quiet)
    except Exception as e:
        log("[!] Rapor gonderilemedi: %s" % e, quiet)


def main():
    ap = argparse.ArgumentParser(description="Endpoint MCP kesif / envanter / credential denetim araci")
    ap.add_argument("-o", "--out-dir", default=os.path.join(os.getcwd(), "mcp_inventory_out"), help="Rapor dizini")
    ap.add_argument("--enumerate", action="store_true", help="Sunuculara baglanip tools/resources/prompts listele (stdio sunucular CALISTIRILIR)")
    ap.add_argument("--enumerate-filter", default=None, help="Sadece adi bu regex ile eslesen sunuculari envanterle")
    ap.add_argument("--include-disabled", action="store_true", help="Devre disi sunuculari da envanterle")
    ap.add_argument("--timeout", type=float, default=20.0, help="Sunucu baslatma/yanit timeout (sn)")
    ap.add_argument("--scan-projects", action="store_true", help="Home altinda proje bazli MCP config dosyalarini ara")
    ap.add_argument("--depth", type=int, default=4, help="Proje taramasi derinligi")
    ap.add_argument("--all-users", action="store_true", help="Tum kullanici profillerini tara (yonetici hakki gerekir)")
    ap.add_argument("--probe-ports", action="store_true", help="Dinleyen portlari HTTP/SSE MCP icin yokla")
    ap.add_argument("--all-ports", action="store_true", help="Raporda tum dinleyen portlari tut (sadece MCP iliskili degil)")
    ap.add_argument("--post-url", default=None, help="Raporu JSON olarak bu URL'ye POST et (SIEM/collector)")
    ap.add_argument("--post-token", default=None, help="POST icin Bearer token (ortam degiskeni MCP_DISCOVERY_TOKEN de kullanilabilir)")
    ap.add_argument("--no-files", action="store_true", help="Dosya yazma; sadece stdout ozet (+ opsiyonel POST)")
    ap.add_argument("--json-stdout", action="store_true", help="Tam raporu stdout'a JSON olarak bas")
    ap.add_argument("-q", "--quiet", action="store_true", help="Ilerleme mesajlarini bastir")
    args = ap.parse_args()

    report = run(args)
    if not args.quiet and not args.json_stdout:
        print_summary(report)
    if args.json_stdout:
        print(json.dumps(report, indent=2, ensure_ascii=False, default=str))
    if not args.no_files:
        j, c = write_outputs(report, args.out_dir, args.quiet)
        log("[*] Rapor: %s\n[*] CSV  : %s" % (j, c), args.quiet)
    if args.post_url:
        post_report(report, args.post_url, args.post_token or os.environ.get("MCP_DISCOVERY_TOKEN"), args.quiet)

    # Exit code: kritik/yuksek bulgu varsa 2, orta 1, temiz 0 (EDR/RMM scriptleri icin)
    levels = report["summary"]["servers_by_risk"]
    if levels.get("critical") or levels.get("high") or report["summary"]["literal_secrets_high"]:
        sys.exit(2)
    if levels.get("medium"):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
