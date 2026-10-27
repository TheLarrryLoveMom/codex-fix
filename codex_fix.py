#!/usr/bin/env python3
"""Idempotent, per-application proxy repair for Linux. Standard library only."""
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

VERSION = "2.0.0"
PROXY_KEYS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
              "http_proxy", "https_proxy", "all_proxy", "no_proxy")
LOCAL_BYPASS = "localhost,127.0.0.1,::1"
BEGIN = "# >>> codex-fix managed >>>"
END = "# <<< codex-fix managed <<<"
MARKER = "# Managed by codex-fix v2"
DESKTOP_KEY = "X-CodexFix-Original-Exec="
PORTS = {10809, 2080, 2081, 7890, 7891, 10808, 1080, 20171, 20172, 12334, 8118}
CLIENTS = re.compile(r"incy|xray|sing-box|v2ray|nekoray|nekobox|throne|hiddify|clash|mihomo|gost", re.I)
# No credentials or inference requests. Status alone is not an end-to-end login test.
ENDPOINTS = (
    ("auth", "https://auth.openai.com/oauth/token", {405}, True),
    ("api", "https://api.openai.com/v1/models", {401}, False),
    ("chatgpt", "https://chatgpt.com/backend-api/codex/models?client_version=0.0.0", {401}, False),
)


def log(message):
    print(message, flush=True)


def run(argv, *, env=None, timeout=15):
    return subprocess.run(argv, env=env, capture_output=True, text=True,
                          errors="replace", timeout=timeout, check=False)


def proxy_env(env):
    return {k: env[k] for k in PROXY_KEYS if env.get(k)}


def with_route(base, route):
    return {**{k: v for k, v in base.items() if k not in PROXY_KEYS}, **route}


def valid_proxy(value):
    """Only explicit, credential-free local proxies are persisted or auto-discovered."""
    try:
        parsed = urlsplit(value)
        return (parsed.scheme in {"http", "https", "socks5", "socks5h"}
                and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
                and parsed.port is not None and 1 <= parsed.port <= 65535
                and not parsed.username and not parsed.password
                and parsed.path in {"", "/"} and not parsed.query and not parsed.fragment
                and not re.search(r"[\s\x00-\x1f]", value))
    except ValueError:
        return False


def route_for(proxy):
    if proxy is None:
        return {}
    if not valid_proxy(proxy):
        raise ValueError("Прокси должен быть локальным URL с портом, без логина/пароля.")
    return {"HTTP_PROXY": proxy, "HTTPS_PROXY": proxy, "ALL_PROXY": proxy,
            "http_proxy": proxy, "https_proxy": proxy, "all_proxy": proxy,
            "NO_PROXY": LOCAL_BYPASS, "no_proxy": LOCAL_BYPASS}


def persistent_route(route):
    """Do not put credentials or arbitrary remote proxy addresses into files."""
    value = route.get("https_proxy") or route.get("HTTPS_PROXY") or route.get("all_proxy") or route.get("ALL_PROXY")
    if not value:
        return {} if not any(route.get(k) for k in PROXY_KEYS if "no_proxy" != k.lower()) else None
    return route_for(value) if valid_proxy(value) else None


class Probe:
    def __init__(self, env, timeout=6):
        self.env = env
        self.timeout = timeout
        self.cache = {}
        self.started = time.monotonic()

    def endpoint(self, item, route):
        name, url, allowed, head = item
        # -q MUST be first: user .curlrc cannot disable TLS, add auth, or change output.
        argv = ["curl", "-q", "--silent", "--show-error", "--proto", "=https",
                "--connect-timeout", str(min(3, self.timeout)), "--max-time", str(self.timeout),
                "--output", os.devnull, "--write-out", "%{http_code} %{content_type}"]
        if head:
            argv.append("--head")
        argv.append(url)
        try:
            result = run(argv, env=with_route(self.env, route), timeout=self.timeout + 2)
            parts = result.stdout.strip().split(maxsplit=1)
            status = int(parts[0]) if parts and parts[0].isdigit() else 0
            json_response = len(parts) > 1 and "application/json" in parts[1].lower()
            ok = result.returncode == 0 and status in allowed and json_response
            return name, ok, f"HTTP {status}" if not result.returncode else f"curl {result.returncode}"
        except (OSError, subprocess.TimeoutExpired):
            return name, False, "тайм-аут/ошибка curl"

    def check(self, route, *, fresh=False):
        key = tuple(sorted(route.items()))
        if fresh or key not in self.cache:
            if time.monotonic() - self.started > 90:
                raise ValueError("Превышен бюджет диагностики (90 секунд). Укажите --proxy для точечной проверки.")
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
                results = list(pool.map(lambda item: self.endpoint(item, route), ENDPOINTS))
            self.cache[key] = (all(item[1] for item in results),
                               ", ".join(f"{name}: {status}" for name, _, status in results))
        return self.cache[key]


def discover_proxies():
    if not shutil.which("ss"):
        log("[!] ss не найден: автопоиск портов недоступен; можно указать --proxy.")
        return []
    try:
        result = run(["ss", "-H", "-ltnp"])
    except (OSError, subprocess.TimeoutExpired):
        return []
    found = set()
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        address, _, port_text = fields[3].rpartition(":")
        if not port_text.isdigit():
            continue
        port = int(port_text)
        address = address.strip("[]")
        if not (1 <= port <= 65535) or (port not in PORTS and not CLIENTS.search(line)):
            continue
        if address in {"0.0.0.0", "*"}:
            address = "127.0.0.1"
        elif address == "::":
            address = "::1"
        try:
            if not ipaddress.ip_address(address).is_loopback:
                continue
        except ValueError:
            continue
        host = f"[{address}]" if ":" in address else address
        # Prefer HTTP across all ports before trying SOCKS (Electron compatibility).
        for scheme in ("http", "socks5h"):
            found.add(f"{scheme}://{host}:{port}")
    return sorted(found, key=lambda url: (not url.startswith("http:"), url))


def process_environments():
    """Read only proxy keys of our own GUI/session processes; never expose secrets."""
    result = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if entry.stat().st_uid != os.getuid():
                continue
            name = (entry / "comm").read_text().strip().lower()
            if name not in {"code", "code-insiders", "chatgpt", "codex", "gnome-shell", "plasmashell", "cinnamon"}:
                continue
            data = (entry / "environ").read_bytes().split(b"\0")
            values = {}
            for item in data:
                key, sep, value = item.partition(b"=")
                if sep and key.decode(errors="replace") in PROXY_KEYS:
                    values[key.decode()] = value.decode(errors="replace")
            result.setdefault(name, []).append(values)
        except (OSError, ValueError):
            continue
    return result


def desktop_quote(value):
    # Desktop Exec escaping differs from shell escaping. Percent is a field-code prefix.
    value = value.replace("%", "%%").replace("\\", "\\\\\\\\")
    for char in ('"', '`', '$'):
        value = value.replace(char, "\\\\" + char)
    return '"' + value + '"'


def wrapper(command, route, gui=False):
    lines = ["#!/bin/sh", MARKER, "unset " + " ".join(PROXY_KEYS)]
    lines += [f"export {key}={shlex.quote(value)}" for key, value in sorted(route.items())]
    argv = [str(command)]
    if gui:
        proxy = route.get("https_proxy")
        argv += (["--proxy-server=" + proxy.replace("socks5h://", "socks5://"),
                  "--proxy-bypass-list=localhost;127.0.0.1;[::1]"] if proxy else ["--no-proxy-server"])
    lines.append("exec " + shlex.join(argv) + ' "$@"')
    return "\n".join(lines) + "\n"


def shell_config(text, commands):
    if (text.count(BEGIN) != text.count(END) or text.count(BEGIN) > 1
            or (BEGIN in text and text.index(BEGIN) > text.index(END))):
        raise ValueError("Повреждён managed-блок shell: автоматическая запись отменена.")
    text = re.sub(re.escape(BEGIN) + r".*?" + re.escape(END) + r"\n?", "", text, flags=re.S)
    # Migrate only the exact legacy marker + adjacent alias, never arbitrary aliases.
    text = re.sub(r"(?m)^# --- AUTO-GENERATED BY CODEX DOCTOR ---\n(?:alias codex=[^\n]*\n?)?", "", text)
    for name in commands:
        if re.search(r"(?m)^\s*(?:alias\s+" + re.escape(name) + r"=|function\s+" + re.escape(name) + r"(?:\s|\()|" + re.escape(name) + r"\s*\(\s*\))", text):
            raise ValueError(f"Обнаружен пользовательский alias/function {name}; сохранён без изменений.")
    block = [BEGIN]
    for name, path in sorted(commands.items()):
        block.append(f"{name}() {{ {shlex.quote(str(path))} \"$@\"; }}")
    block.append(END)
    return text.rstrip("\n") + "\n\n" + "\n".join(block) + "\n"


@dataclass
class Target:
    name: str
    command: str
    gui: bool = False


def installed_targets():
    targets = []
    for name in ("codex", "code", "code-insiders", "chatgpt", "codex-desktop"):
        command = shutil.which(name)
        if command:
            # A user may have added our private bin directory to PATH. Never wrap
            # a wrapper in itself on a later run: recover its original executable.
            seen = set()
            while command not in seen:
                seen.add(command)
                try:
                    with open(command, "rb") as stream:
                        header = stream.read(8192).decode("utf-8", errors="replace")
                except OSError:
                    break
                if not header.startswith("#!/bin/sh\n" + MARKER + "\n"):
                    break
                execution = next((line for line in header.splitlines() if line.startswith("exec ")), "")
                parsed = shlex.split(execution)
                if len(parsed) < 2 or not os.path.isabs(parsed[1]) or parsed[1] in seen:
                    raise ValueError(f"Обнаружена рекурсивная/повреждённая обёртка {name}.")
                command = parsed[1]
            # Keep launchers/symlinks, rather than resolving npm/electron entry points.
            targets.append(Target(name, os.path.abspath(command), name != "codex"))
    return targets


def desktop_kind(text):
    """Classify native launchers, excluding browser PWAs, Flatpak and Snap sandboxes."""
    matches = re.findall(r"(?m)^Exec=(.*)$", text)
    if not matches:
        return None
    try:
        command = shlex.split(matches[0])[0]
    except (ValueError, IndexError):
        return None
    basename = Path(command).name.lower()
    if basename in {"flatpak", "snap", "env"} or "/snap/" in command:
        return "unsupported" if re.search(r"codex|chatgpt|visual studio code", text, re.I) else None
    if basename in {"code", "code-insiders", "chatgpt", "codex", "codex-desktop", "codex-launcher"}:
        return basename if basename in {"code", "code-insiders"} else "desktop"
    if basename.endswith(".appimage") and re.search(r"codex|chatgpt", basename):
        return "desktop"
    return None


def original_desktop(text):
    """Recover per-section original Exec saved by this tool, preserving all other keys."""
    lines = text.splitlines()
    out = []
    for line in lines:
        if line.startswith(DESKTOP_KEY):
            if not out or not out[-1].startswith("Exec="):
                raise ValueError("Повреждён managed desktop-файл.")
            out[-1] = "Exec=" + base64.b64decode(line[len(DESKTOP_KEY):], validate=True).decode()
        else:
            out.append(line)
    return "\n".join(out) + "\n"


def desktop_patch(text, route, bin_dir, desktop_id):
    text = original_desktop(text)
    writes = {}
    lines = []
    for index, line in enumerate(text.splitlines()):
        if line.startswith("DBusActivatable="):
            line = "DBusActivatable=false"  # Ensure the Exec environment is actually used.
        if line.startswith("Exec="):
            original = line[5:]
            # Preserve field codes and argument quoting byte-for-byte after the executable.
            match = re.match(r'("(?:\\.|[^"\\])*"|[^\s]+)(.*)$', original)
            if not match:
                raise ValueError("Не удалось разобрать desktop Exec.")
            command = shlex.split(match[1])[0]
            resolved = command if os.path.isabs(command) else shutil.which(command)
            if not resolved or not os.access(resolved, os.X_OK):
                raise ValueError("Исполняемый файл desktop-приложения не найден.")
            if re.search(r"--(?:proxy-server|proxy-pac-url|no-proxy-server)\b", match[2]):
                raise ValueError("Ярлык содержит собственные proxy-флаги; требуется ручная проверка.")
            digest = hashlib.sha256(f"{desktop_id}:{index}".encode()).hexdigest()[:16]
            path = bin_dir / ("desktop-" + digest)
            writes[path] = (wrapper(resolved, route, gui=True).encode(), 0o700)
            lines.append("Exec=" + desktop_quote(str(path)) + match[2])
            lines.append(DESKTOP_KEY + base64.b64encode(original.encode()).decode())
        else:
            lines.append(line)
    return "\n".join(lines) + "\n", writes


def atomic_write(path, data, mode):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temp = tempfile.mkstemp(prefix=".codex-fix-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


class Store:
    def __init__(self, home):
        self.home = home.resolve()
        self.root = self.home / ".local/share/codex-fix"
        self.bin = self.root / "bin"
        self.manifest = self.root / "manifest.json"
        self.state = json.loads(self.manifest.read_text()) if self.manifest.exists() else {"version": 2, "files": {}, "routes": {}}
        if (not isinstance(self.state, dict) or self.state.get("version") != 2
                or not isinstance(self.state.get("files"), dict)
                or not isinstance(self.state.get("routes"), dict)):
            raise ValueError("Повреждён manifest.json или неизвестна его версия.")
        for route in self.state["routes"].values():
            if (not isinstance(route, dict) or any(k not in PROXY_KEYS or not isinstance(v, str)
                                                  for k, v in route.items())
                    or persistent_route(route) != route):
                raise ValueError("Некорректный сохранённый маршрут в manifest.json.")
        for name, record in self.state["files"].items():
            if (not isinstance(record, dict) or not isinstance(name, str)
                    or Path(name).is_absolute() or ".." in Path(name).parts
                    or not re.fullmatch(r"[a-f0-9]{64}", str(record.get("installed_sha256", "")))
                    or "original" not in record or "mode" not in record):
                raise ValueError("Некорректная запись резервной копии в manifest.json.")
            if record["original"] is not None:
                if not isinstance(record["mode"], int) or not 0 <= record["mode"] <= 0o7777:
                    raise ValueError("Некорректные права резервной копии.")
                try:
                    base64.b64decode(record["original"], validate=True)
                except (ValueError, TypeError) as error:
                    raise ValueError("Повреждена резервная копия в manifest.json.") from error

    def safe_path(self, path):
        if path.is_symlink() or not path.resolve().is_relative_to(self.home):
            raise ValueError(f"Отказ от изменения symlink/пути за пределами домашней папки: {path}")
        if path.exists() and not path.is_file():
            raise ValueError(f"Ожидался обычный файл: {path}")

    def pending(self, writes):
        result = {}
        for path, (data, mode) in writes.items():
            self.safe_path(path)
            if not path.exists() or path.read_bytes() != data or stat.S_IMODE(path.stat().st_mode) != mode:
                result[path] = (data, mode)
        return result

    def apply(self, writes, routes):
        writes = self.pending(writes)
        if not writes:
            return 0
        self.safe_path(self.manifest)
        # The manifest retains the first original version, not the previous repaired version.
        state = json.loads(json.dumps(self.state))
        before = {}
        for path in writes:
            before[path] = (path.read_bytes(), stat.S_IMODE(path.stat().st_mode)) if path.exists() else None
            key = str(path.relative_to(self.home))
            digest = hashlib.sha256(before[path][0]).hexdigest() if before[path] else None
            record = state["files"].get(key)
            if record and digest != record["installed_sha256"]:
                raise ValueError(f"Файл изменён вручную после фикса: {path}; сохранён без перезаписи.")
            if record is None:
                record = {"original": base64.b64encode(before[path][0]).decode() if before[path] else None,
                          "mode": before[path][1] if before[path] else None}
                state["files"][key] = record
            record["installed_sha256"] = hashlib.sha256(writes[path][0]).hexdigest()
        state["routes"].update(routes)
        done = []
        try:
            for path, (data, mode) in writes.items():
                atomic_write(path, data, mode)
                done.append(path)
                if path.read_bytes() != data:
                    raise OSError(f"Проверка записанного файла не прошла: {path}")
            atomic_write(self.manifest, (json.dumps(state, indent=2) + "\n").encode(), 0o600)
        except BaseException:
            for path in reversed(done):
                if before[path] is None:
                    path.unlink(missing_ok=True)
                else:
                    atomic_write(path, *before[path])
            raise
        self.state = state
        return len(writes)

    def restore(self, check=False):
        work = []
        for name, record in self.state["files"].items():
            path = self.home / name
            self.safe_path(path)
            if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest() != record["installed_sha256"]:
                raise ValueError(f"Откат отменён: файл изменён или удалён пользователем: {path}")
            original = base64.b64decode(record["original"]) if record["original"] is not None else None
            work.append((path, original, record["mode"]))
        if check:
            return len(work)
        before = {path: (path.read_bytes(), stat.S_IMODE(path.stat().st_mode)) for path, _, _ in work}
        done = []
        try:
            for path, original, mode in work:
                if original is None:
                    path.unlink()
                else:
                    atomic_write(path, original, mode)
                done.append(path)
            if work:
                self.manifest.unlink()
        except BaseException:
            for path in reversed(done):
                atomic_write(path, *before[path])
            raise
        return len(work)


def desktop_files(home):
    # Same desktop ID in the user directory takes precedence over the system one.
    roots = [Path("/usr/share/applications"), Path("/usr/local/share/applications"),
             home / ".local/share/applications"]
    files = {}
    for root in roots:
        if root.is_dir():
            for path in sorted(root.glob("*.desktop")):
                files[path.name] = path
    return files


def gui_base(processes):
    for name in ("gnome-shell", "plasmashell", "cinnamon"):
        if processes.get(name):
            return processes[name][0]
    # Do not assume a terminal's exported proxy exists in desktop sessions.
    return {}


def doctor(args, *, home=None, env=None):
    home = home or Path.home()
    env = dict(os.environ if env is None else env)
    store = Store(home)
    if args.restore:
        count = store.restore(args.check)
        log(f"{'Будет восстановлено' if args.check else 'Восстановлено'} файлов: {count}.")
        return 3 if args.check and count else 0
    if not shutil.which("curl"):
        raise ValueError("Не найден curl. Установите пакет curl и повторите запуск.")
    probe = Probe(env, args.timeout)
    processes = process_environments()
    desktop_env = gui_base(processes)
    targets = installed_targets()
    log(f"Codex Fix {VERSION} — {'только проверка' if args.check else 'автоматическая проверка и исправление'}")
    log("Обнаружены команды: " + (", ".join(t.name for t in targets) or "не найдены"))
    extensions = list((home / ".vscode/extensions").glob("openai.chatgpt-*/package.json"))
    extensions += list((home / ".vscode-insiders/extensions").glob("openai.chatgpt-*/package.json"))
    log(f"Расширение Codex для VS Code: {'найдено' if extensions else 'не найдено в стандартных каталогах'}.")
    if not any(t.name.startswith("code") and t.gui for t in targets):
        log("[i] VS Code не найден в PATH; проверяю также desktop-ярлыки.")
    selected = None
    writes = {}
    routes = {}
    commands = {}
    failures = []

    # Warn about explicit VS Code overrides without trying to rewrite arbitrary JSONC.
    # These settings can override process env and therefore prevent a complete repair.
    for folder in ("Code", "Code - Insiders"):
        settings = home / ".config" / folder / "User/settings.json"
        if settings.is_file():
            settings_text = settings.read_text()
            overrides = re.findall(r'"(http\.proxy|chatgpt\.cliExecutable)"\s*:\s*("(?:\\.|[^"\\])*"|null)', settings_text)
            for key, raw in overrides:
                if json.loads(raw):
                    log(f"[!] {folder}: задан {key}; он может перекрывать исправление. Проверьте настройку в редакторе.")
                    failures.append(f"{folder}:{key}")

    def choose():
        nonlocal selected
        if selected is not None:
            return selected
        candidates = [route_for(args.proxy)] if args.proxy else []
        for existing in [proxy_env(env), *store.state["routes"].values()]:
            saved = persistent_route(existing)
            if saved is not None and saved not in candidates:
                candidates.append(saved)
        if {} not in candidates:
            candidates.append({})
        for candidate in candidates:
            ok, _ = probe.check(candidate)
            if ok:
                selected = candidate
                return selected
        for proxy in discover_proxies():
            candidate = route_for(proxy)
            if probe.check(candidate)[0]:
                selected = candidate
                return selected
        raise ValueError("Не найден маршрут ко всем трём сервисам. Проверьте VPN, DNS и доступ к OpenAI. Файлы не изменены.")

    def repair_route(key, current):
        known = store.state["routes"].get(key, current)
        ok, detail = probe.check(known)
        if ok:
            log(f"[OK] {key}: {detail}")
            return known, key in store.state["routes"]
        log(f"[FIX] {key}: {detail}")
        fixed = choose()
        routes[key] = fixed
        return fixed, True

    for target in targets:
        route, managed = repair_route(target.name, desktop_env if target.gui else proxy_env(env))
        if managed:
            path = store.bin / target.name
            writes[path] = (wrapper(target.command, route, target.gui).encode(), 0o700)
            commands[target.name] = path
        if target.gui and processes.get(target.name):
            if any(not probe.check(item)[0] for item in processes[target.name]):
                log(f"[!] {target.name} уже запущен со старым окружением; потребуется полностью закрыть и открыть приложение.")

    desktop_count = 0
    for name, path in desktop_files(home).items():
        try:
            text = path.read_text()
            original = original_desktop(text)
            kind = desktop_kind(original)
            if not kind:
                continue
            if kind == "unsupported":
                log(f"[!] {name}: sandbox/нестандартный Exec; автоматическое изменение пропущено.")
                failures.append(name)
                continue
            desktop_count += 1
            route, managed = repair_route("desktop:" + name, desktop_env)
            if managed:
                patched, launchers = desktop_patch(original, route, store.bin, name)
                destination = home / ".local/share/applications" / name
                writes[destination] = (patched.encode(), 0o600)
                writes.update(launchers)
        except (ValueError, OSError) as error:
            log(f"[!] {name}: {error}")
            failures.append(name)

    if not targets and not desktop_count:
        log("[!] Codex/VS Code/ChatGPT не обнаружены; установите нужное приложение. Изменений нет.")
        return 1

    if commands:
        configs = [home / ".bashrc", home / ".zshrc"]
        configs = [path for path in configs if path.exists()] or [home / ".bashrc"]
        for path in configs:
            try:
                text = path.read_text() if path.exists() else ""
                updated = shell_config(text, commands)
                mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o600
                writes[path] = (updated.encode(), mode)
            except ValueError as error:
                log(f"[!] {path.name}: {error} Обёртки доступны в {store.bin}.")
                failures.append(path.name)

    pending = store.pending(writes)
    if not pending:
        log("Изменения не требуются: проверенные маршруты и управляемые файлы исправны.")
        log("Это проверка сети; вход в аккаунт, квота и генерация ответа проверяются в самом Codex.")
        return 1 if failures else 0
    for path in pending:
        log(f"  {'План' if args.check else 'Исправление'}: {path}")
    if args.check:
        return 3
    # Recheck before writes; a transient success must not cause persistent broken settings.
    for route in {json.dumps(r, sort_keys=True) for r in routes.values()}:
        if not probe.check(json.loads(route), fresh=True)[0]:
            raise ValueError("Повторная проверка маршрута не прошла. Файлы не изменены.")
    count = store.apply(writes, routes)
    log(f"Готово: изменено файлов — {count}. Резервные копии: {store.manifest}")
    log("Новый терминал подхватит обёртки; для открытых GUI сохраните работу и полностью перезапустите приложение.")
    log("Проверена сетевая доступность, а не вход в аккаунт/квота/генерация ответа. Авторизация остаётся за приложением.")
    return 1 if failures else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="Автоматический сетевой фикс Codex CLI, VS Code и ChatGPT/Codex Desktop для Linux.")
    parser.add_argument("--fix", action="store_true", help="автоматически проверить и исправить все найденные компоненты (режим по умолчанию)")
    parser.add_argument("--check", "--dry-run", action="store_true", help="только диагностика, без записи файлов")
    parser.add_argument("--proxy", help="предпочтительный локальный http(s):// или socks5(h):// прокси")
    parser.add_argument("--timeout", type=int, default=6, choices=range(1, 31), metavar="1..30", help="тайм-аут одной проверки, секунды")
    parser.add_argument("--restore", action="store_true", help="восстановить файлы до первого исправления")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args(argv)
    if args.fix and (args.check or args.restore):
        parser.error("--fix нельзя сочетать с --check/--dry-run или --restore")
    if sys.version_info < (3, 9):
        parser.error("требуется Python 3.9 или новее")
    if sys.platform != "linux":
        parser.error("поддерживается только Linux")
    if os.geteuid() == 0:
        parser.error("запускайте от обычного пользователя, без sudo")
    try:
        if args.proxy:
            route_for(args.proxy)
        # Linux abstract socket: per-user lock without leaving lock files on healthy runs.
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as lock:
            name = hashlib.sha256(str(Path.home()).encode()).hexdigest()[:16]
            try:
                lock.bind(f"\0codex-fix-{os.getuid()}-{name}")
            except OSError as error:
                raise ValueError("Другой экземпляр codex-fix уже выполняется.") from error
            return doctor(args)
    except KeyboardInterrupt:
        log("Проверка прервана пользователем.")
        return 130
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        log(f"[Ошибка] {error}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
