from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import selectors
import shutil
import stat
import subprocess
import tempfile
import time
import fcntl
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit, urlunsplit

PLAN_TTL_SECONDS = 10 * 60
WARN_FILE_BYTES = 50 * 1024 * 1024
BLOCK_FILE_BYTES = 100 * 1024 * 1024
BLOCK_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_FILES = 50_000
MAX_CURRENT_SCAN_BYTES = 100 * 1024 * 1024
MAX_HISTORY_SCAN_BYTES = 100 * 1024 * 1024
MAX_HISTORY_BLOB_SCAN_BYTES = 50 * 1024 * 1024
MAX_HISTORY_PATHS = 200_000
MAX_HISTORY_PATH_OUTPUT_BYTES = 32 * 1024 * 1024
MAX_HISTORY_OBJECTS = 200_000
MAX_HISTORY_OBJECT_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_ATTRIBUTES_FILE_BYTES = 1024 * 1024

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
CODEX_HOME = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))).expanduser()
STATE_DIR = CODEX_HOME / "github-project-uploader"
REGISTRY_PATH = STATE_DIR / "projects.json"
PLANS_PATH = STATE_DIR / "plans.json"
LOCK_PATH = STATE_DIR / "state.lock"
ISOLATED_GIT_CONFIG_ENV = {
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_SYSTEM": "/dev/null",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_ATTR_NOSYSTEM": "1",
}
SAFE_PUSH_ENV = {
    **ISOLATED_GIT_CONFIG_ENV,
    "GIT_SSH_COMMAND": (
        "/usr/bin/ssh -F /dev/null -o BatchMode=yes -o ConnectTimeout=30 "
        "-o HostName=github.com -o Port=22 -o ProxyCommand=none -o ProxyJump=none "
        "-o ClearAllForwardings=yes -o PermitLocalCommand=no"
    ),
}


class UploadError(RuntimeError):
    pass


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key", re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")),
    ("github_token", re.compile(r"(?:gh[pousr]_[A-Za-z0-9_]{20,255}|github_pat_[A-Za-z0-9_]{20,255})")),
    ("openai_api_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("url_credentials", re.compile(r"\b(?:https?|ssh|git\+ssh)://[^\s/@:]+:[^\s/@]{4,}@")),
    (
        "assigned_secret",
        re.compile(
            r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password)"
            r"\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{16,}"
        ),
    ),
)

# Assemble these markers at runtime so this scanner does not mistake its own
# implementation for a service-account document. Detection of project content
# remains unchanged.
SERVICE_ACCOUNT_TYPE_MARKER = '"service_' + 'account"'
PRIVATE_KEY_FIELD_MARKER = '"private_' + 'key"'

SENSITIVE_EXACT_NAMES = {
    ".env",
    ".envrc",
    ".git-credentials",
    ".authinfo",
    ".htpasswd",
    ".pgpass",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "credentials.json",
    "service-account.json",
    "service_account.json",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
}
SENSITIVE_SUFFIXES = {".pem", ".key", ".p12", ".pfx"}
NOISY_PARTS = {
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".cache",
    "dist",
    "build",
    "coverage",
    "datasets",
}


def _redact_secret_text(text: str) -> str:
    value = text
    for _, pattern in SECRET_PATTERNS:
        value = pattern.sub("[REDACTED]", value)
    return value


def _safe_error(text: str) -> str:
    text = re.sub(r"https://[^/@\s]+@github\.com", "https://***@github.com", text)
    return _redact_secret_text(text).strip()[:2000]


def _command_environment(args: list[str], env_overrides: dict[str, str] | None = None) -> dict[str, str]:
    env = os.environ.copy()
    for key in list(env):
        if key.startswith("GIT_"):
            env.pop(key, None)
    if Path(args[0]).name == "git":
        env.update(ISOLATED_GIT_CONFIG_ENV)
    env.update({"GH_PROMPT_DISABLED": "1", "GIT_TERMINAL_PROMPT": "0"})
    if env_overrides:
        env.update(env_overrides)
    return env


def run_command(
    args: list[str],
    *,
    cwd: Path | None = None,
    input_text: str | None = None,
    check: bool = True,
    timeout: int = 180,
    env_overrides: dict[str, str] | None = None,
) -> CommandResult:
    if not args or any(not isinstance(arg, str) for arg in args):
        raise UploadError("内部命令参数无效。")
    forbidden = {"--force", "--mirror", "--force-with-lease"}
    if forbidden.intersection(args):
        raise UploadError("安全策略禁止强制推送或镜像推送。")
    completed = subprocess.run(
        args,
        cwd=str(cwd) if cwd else None,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_command_environment(args, env_overrides),
        timeout=timeout,
        shell=False,
        check=False,
    )
    result = CommandResult(completed.returncode, completed.stdout, completed.stderr)
    if check and completed.returncode != 0:
        detail = _safe_error(completed.stderr or completed.stdout or f"exit {completed.returncode}")
        raise UploadError(f"命令执行失败：{detail}")
    return result


def _run_bounded_stdout(args: list[str], *, max_bytes: int, timeout: int) -> str:
    if not args or max_bytes < 1 or timeout < 1:
        raise UploadError("内部有界命令参数无效。")
    process = subprocess.Popen(
        args,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=_command_environment(args),
        shell=False,
    )
    if process.stdout is None:
        process.kill()
        raise UploadError("无法读取安全检查命令输出；上传已停止。")
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    output = bytearray()
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                process.kill()
                process.wait()
                raise UploadError("安全检查命令超时；上传已停止。")
            events = selector.select(min(remaining, 1.0))
            if not events:
                if process.poll() is not None:
                    chunk = os.read(process.stdout.fileno(), 64 * 1024)
                    if chunk:
                        output.extend(chunk)
                        if len(output) > max_bytes:
                            process.kill()
                            process.wait()
                            raise UploadError("安全检查输出超过上限；上传已停止。")
                    else:
                        selector.unregister(process.stdout)
                continue
            for key, _ in events:
                chunk = os.read(key.fileobj.fileno(), 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                output.extend(chunk)
                if len(output) > max_bytes:
                    process.kill()
                    process.wait()
                    raise UploadError("安全检查输出超过上限；上传已停止。")
        returncode = process.wait(timeout=max(1, int(deadline - time.monotonic()) + 1))
    finally:
        selector.close()
        process.stdout.close()
        if process.poll() is None:
            process.kill()
            process.wait()
    if returncode != 0:
        raise UploadError("无法完整读取 Git 历史；上传已停止。")
    return bytes(output).decode("utf-8", errors="surrogateescape")


def _git_executable() -> str:
    system_git = Path("/usr/bin/git")
    if system_git.is_file() and os.access(system_git, os.X_OK):
        return str(system_git)
    return shutil.which("git") or "/usr/bin/git"


def _git_command(path: Path, *args: str) -> list[str]:
    return [
        _git_executable(),
        "--no-replace-objects",
        "--no-lazy-fetch",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.trustctime=true",
        "-c",
        "core.checkStat=default",
        "-c",
        "core.fileMode=true",
        "-c",
        "commit.gpgSign=false",
        "-c",
        "core.attributesFile=/dev/null",
        "-c",
        "core.excludesFile=/dev/null",
        "-c",
        "maintenance.auto=false",
        "-c",
        "gc.auto=0",
        "-C",
        str(path),
        *args,
    ]


def _git_push_command(git_dir: Path, remote_url: str, oid: str, branch: str) -> list[str]:
    if not re.fullmatch(r"[0-9a-fA-F]{40,64}", oid):
        raise UploadError("无法确认要推送的 Git 提交；请重新预检。")
    ref = f"refs/heads/{branch}"
    checked = run_command([_git_executable(), "check-ref-format", ref], check=False, timeout=30)
    if checked.returncode != 0:
        raise UploadError("当前分支名不能安全推送；请切换分支后重试。")
    return [
        _git_executable(),
        "--no-replace-objects",
        "--no-lazy-fetch",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "push.followTags=false",
        "-c",
        "push.gpgSign=false",
        "-c",
        "push.recurseSubmodules=no",
        "-c",
        "maintenance.auto=false",
        "-c",
        "gc.auto=0",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "protocol.ext.allow=never",
        f"--git-dir={git_dir}",
        "push",
        "--no-follow-tags",
        "--no-push-option",
        "--no-verify",
        "--recurse-submodules=no",
        remote_url,
        f"{oid}:{ref}",
    ]


def _verify_remote_branch(cwd: Path, remote_url: str, oid: str, branch: str) -> None:
    ref = f"refs/heads/{branch}"
    result = run_command(
        [
            _git_executable(),
            "--no-replace-objects",
            "--no-lazy-fetch",
            "-c",
            "maintenance.auto=false",
            "-c",
            "gc.auto=0",
            "-c",
            "protocol.file.allow=never",
            "-c",
            "protocol.ext.allow=never",
            "ls-remote",
            "--refs",
            remote_url,
            ref,
        ],
        cwd=cwd,
        timeout=180,
        env_overrides=SAFE_PUSH_ENV,
    )
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    fields = lines[0].split("\t", 1) if len(lines) == 1 else []
    if len(fields) != 2 or fields[0].lower() != oid.lower() or fields[1] != ref:
        raise UploadError("推送命令结束，但 GitHub 分支未指向已确认提交；请检查仓库后重新预检。")


@contextmanager
def _isolated_push_repository(path: Path, oid: str):
    if _is_shallow_repository(path):
        raise UploadError("浅克隆仓库的历史不完整；未执行推送。请先完整获取全部历史。")
    common = run_command(
        _git_command(path, "rev-parse", "--path-format=absolute", "--git-common-dir"),
        check=False,
        timeout=30,
    )
    if common.returncode != 0 or not common.stdout.strip():
        raise UploadError("无法定位 Git 对象数据库；未执行推送。")
    try:
        objects = (Path(common.stdout.strip()) / "objects").resolve(strict=True)
    except OSError as exc:
        raise UploadError("无法安全读取 Git 对象数据库；未执行推送。") from exc
    if not objects.is_dir():
        raise UploadError("Git 对象数据库无效；未执行推送。")
    object_format = _git_object_format(path)
    with tempfile.TemporaryDirectory(prefix="codex-github-transport-") as temporary:
        transport_root = Path(temporary)
        git_dir = transport_root / "transport.git"
        initialized = run_command(
            [
                _git_executable(),
                "--no-replace-objects",
                "--no-lazy-fetch",
                "-c",
                "maintenance.auto=false",
                "-c",
                "gc.auto=0",
                "init",
                "--quiet",
                "--bare",
                "--template=",
                f"--object-format={object_format}",
                str(git_dir),
            ],
            timeout=60,
        )
        if initialized.returncode != 0:
            raise UploadError("无法建立隔离的 Git 传输环境；未执行推送。")
        transport_env = {**SAFE_PUSH_ENV, "GIT_OBJECT_DIRECTORY": str(objects)}
        object_check = run_command(
            [
                _git_executable(),
                "--no-replace-objects",
                "--no-lazy-fetch",
                f"--git-dir={git_dir}",
                "cat-file",
                "-e",
                f"{oid}^{{commit}}",
            ],
            check=False,
            timeout=60,
            env_overrides=transport_env,
        )
        if object_check.returncode != 0:
            raise UploadError("隔离传输环境无法读取已确认提交；未执行推送。")
        yield transport_root, git_dir, transport_env


def _gh_executable() -> str:
    candidates = [
        str(Path.home() / ".local" / "bin" / "gh"),
        "/opt/homebrew/bin/gh",
        "/usr/local/bin/gh",
        shutil.which("gh"),
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    raise UploadError("未找到 GitHub CLI（gh）。请先在 Codex 中完成 GitHub 登录设置。")


def _ensure_state_dir() -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(STATE_DIR, 0o700)
    except OSError:
        pass


@contextmanager
def _state_lock():
    _ensure_state_dir()
    fd = os.open(LOCK_PATH, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        os.chmod(LOCK_PATH, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise UploadError(f"本地状态文件损坏：{path.name}。请在 Codex 中请求修复。") from exc


def _write_json(path: Path, value: Any) -> None:
    _ensure_state_dir()
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    payload = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        if temporary.exists():
            temporary.unlink(missing_ok=True)


def _load_registry() -> dict[str, Any]:
    value = _read_json(REGISTRY_PATH, {"version": 1, "projects": []})
    if not isinstance(value, dict) or not isinstance(value.get("projects"), list):
        raise UploadError("项目列表格式无效。")
    return value


def _load_plans() -> dict[str, Any]:
    value = _read_json(PLANS_PATH, {"version": 1, "plans": {}})
    if not isinstance(value, dict) or not isinstance(value.get("plans"), dict):
        raise UploadError("上传计划文件格式无效。")
    now = time.time()
    value["plans"] = {
        key: plan
        for key, plan in value["plans"].items()
        if isinstance(plan, dict) and now - float(plan.get("created_at", 0)) < 24 * 60 * 60
    }
    return value


def _validate_project_path(raw_path: str) -> Path:
    if not raw_path.strip():
        raise UploadError("请提供项目目录路径。")
    path = Path(raw_path).expanduser().resolve(strict=True)
    if not path.is_dir():
        raise UploadError("所选路径不是目录。")
    home = Path.home().resolve()
    forbidden_exact = {
        Path("/").resolve(),
        home,
        (home / "Documents").resolve(),
        (home / "Desktop").resolve(),
        (home / "Downloads").resolve(),
        (home / "Library").resolve(),
        CODEX_HOME.resolve(),
    }
    if path in forbidden_exact:
        raise UploadError("该目录范围过大；请选择具体项目文件夹。")
    sensitive_roots = [
        home / ".ssh",
        home / ".gnupg",
        home / ".aws",
        home / ".azure",
        home / ".kube",
        home / ".docker",
        home / ".config",
        home / ".password-store",
        home / "Library",
        CODEX_HOME,
    ]
    for root in sensitive_roots:
        root = root.resolve()
        if path == root or root in path.parents:
            raise UploadError("安全策略不允许注册凭据或系统数据目录。")
    return path


def _git_marker_kind(path: Path) -> str | None:
    marker = path / ".git"
    try:
        info = marker.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise UploadError("无法安全检查项目根目录的 .git；请选择有效的项目目录。") from exc
    if stat.S_ISLNK(info.st_mode):
        raise UploadError("项目根目录的 .git 是符号链接；为避免写入项目外路径，上传已停止。")
    if stat.S_ISDIR(info.st_mode):
        return "directory"
    if not stat.S_ISREG(info.st_mode):
        raise UploadError("项目根目录包含异常 .git；上传已停止。")
    try:
        content = marker.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        raise UploadError("项目根目录的 .git 文件无法验证；上传已停止。") from exc
    if len(content) > 4096 or not re.fullmatch(r"gitdir: [^\r\n]+\r?\n?", content):
        raise UploadError("项目根目录包含格式异常的 .git 文件；上传已停止。")
    raw_target = content.split(":", 1)[1].strip()
    target = Path(raw_target)
    if not target.is_absolute():
        target = marker.parent / target
    try:
        if not target.resolve(strict=True).is_dir():
            raise UploadError("项目根目录的 .git 指向无效目录；上传已停止。")
    except OSError as exc:
        raise UploadError("项目根目录的 .git 指向无效目录；上传已停止。") from exc
    return "gitfile"


def _looks_like_bare_git_dir(path: Path) -> bool:
    try:
        return (path / "HEAD").is_file() and (path / "objects").is_dir() and (path / "refs").is_dir()
    except OSError:
        return True


def _git_root(path: Path) -> Path | None:
    marker_kind = _git_marker_kind(path)
    bare = run_command(
        _git_command(path, "rev-parse", "--is-bare-repository"),
        check=False,
        timeout=30,
    )
    if bare.returncode == 0 and bare.stdout.strip().lower() == "true":
        raise UploadError("所选目录是 bare Git 仓库；不能把 Git 管理数据当作项目文件上传。")
    if marker_kind is None and _looks_like_bare_git_dir(path):
        raise UploadError("所选目录看起来是 Git 管理目录；不能把内部对象或引用当作项目文件上传。")
    result = run_command(
        _git_command(path, "rev-parse", "--show-toplevel"),
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        if marker_kind is not None:
            raise UploadError("检测到 .git，但无法把它验证为可用的 Git 仓库；上传已停止。")
        return None
    if not result.stdout.strip():
        raise UploadError("Git 返回了空的项目根目录；上传已停止。")
    try:
        return Path(result.stdout.strip()).resolve()
    except OSError:
        return None


def _safe_remote_url(url: str) -> str:
    value = url.strip()
    scheme_match = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*://)([^/?#]*)(.*)$", value, flags=re.DOTALL)
    if scheme_match:
        authority = scheme_match.group(2).rsplit("@", 1)[-1]
        scrubbed = f"{scheme_match.group(1)}{authority}{scheme_match.group(3)}"
        try:
            parts = urlsplit(scrubbed)
            hostname = parts.hostname or ""
            port = f":{parts.port}" if parts.port else ""
            if not hostname:
                return "[REDACTED_REMOTE]"
            value = urlunsplit((parts.scheme, hostname + port, parts.path, "", ""))
        except ValueError:
            return "[REDACTED_REMOTE]"
    else:
        value = re.split(r"[?#]", value, maxsplit=1)[0]
        if "@" in value:
            value = f"***@{value.rsplit('@', 1)[1]}"
    return _redact_secret_text(value)


def _github_slug_from_remote(url: str) -> str | None:
    value = _safe_remote_url(url).strip().removesuffix(".git").rstrip("/")
    match = re.match(r"^(?:git|\*\*\*)@github\.com:([^/]+/[^/]+)$", value)
    if match:
        return match.group(1).lower()
    match = re.match(r"^ssh://(?:[^/@]+@)?github\.com/([^/]+/[^/]+)$", value)
    if match:
        return match.group(1).lower()
    match = re.match(r"^https?://github\.com/([^/]+/[^/]+)$", value)
    if match:
        return match.group(1).lower()
    return None


def _git_config_values(path: Path, key: str) -> list[str]:
    result = run_command(
        _git_command(path, "config", "--null", "--get-all", key),
        check=False,
        timeout=30,
    )
    if result.returncode == 1:
        return []
    if result.returncode != 0:
        raise UploadError("无法可靠读取仓库远程配置；上传已停止。")
    return [value for value in result.stdout.split("\0") if value]


def _origin(path: Path) -> str | None:
    values = _git_config_values(path, "remote.origin.url")
    if not values:
        return None
    if len(values) != 1:
        raise UploadError("origin 包含多个获取地址；上传已停止。")
    return _safe_remote_url(values[0])


def _push_urls(path: Path) -> list[str]:
    values = _git_config_values(path, "remote.origin.pushurl")
    if not values:
        origin = _git_config_values(path, "remote.origin.url")
        values = origin if len(origin) == 1 else []
    return [_safe_remote_url(value) for value in values]


def _branch(path: Path) -> str | None:
    result = run_command(
        _git_command(path, "symbolic-ref", "--quiet", "--short", "HEAD"),
        check=False,
        timeout=30,
    )
    if result.returncode == 1:
        return None
    if result.returncode != 0 or not result.stdout.strip():
        raise UploadError("无法可靠读取当前 Git 分支；上传已停止。")
    return result.stdout.strip()


def _head(path: Path) -> str | None:
    result = run_command(
        _git_command(path, "rev-parse", "--verify", "HEAD^{commit}"),
        check=False,
        timeout=30,
    )
    value = result.stdout.strip()
    if result.returncode == 0 and re.fullmatch(r"[0-9a-fA-F]{40,64}", value):
        return value.lower()
    symbolic = run_command(
        _git_command(path, "symbolic-ref", "--quiet", "HEAD"),
        check=False,
        timeout=30,
    )
    if symbolic.returncode == 0 and symbolic.stdout.strip():
        ref = symbolic.stdout.strip()
        exists = run_command(
            _git_command(path, "show-ref", "--verify", "--quiet", ref),
            check=False,
            timeout=30,
        )
        if exists.returncode == 1:
            return None
    raise UploadError("无法可靠读取当前 Git HEAD；上传已停止。")


def _suggested_repo_name(path: Path) -> str:
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", path.name).strip("-.")
    return (name or "project")[:100]


def register_project(path: str, display_name: str = "") -> dict[str, Any]:
    resolved = _validate_project_path(path)
    git_root = _git_root(resolved)
    if git_root is not None and git_root != resolved:
        raise UploadError(f"该文件夹属于更大的 Git 项目。请注册项目根目录：{_redact_secret_text(str(git_root))}")
    with _state_lock():
        registry = _load_registry()
        for item in registry["projects"]:
            if Path(item["path"]).resolve() == resolved:
                if display_name.strip():
                    item["name"] = display_name.strip()[:120]
                    _write_json(REGISTRY_PATH, registry)
                return {"registered": False, "project": _project_summary(item)}
        item = {
            "id": secrets.token_urlsafe(12),
            "name": (display_name.strip() or resolved.name)[:120],
            "path": str(resolved),
            "added_at": int(time.time()),
        }
        registry["projects"].append(item)
        _write_json(REGISTRY_PATH, registry)
    return {"registered": True, "project": _project_summary(item)}


def _project_summary(item: dict[str, Any]) -> dict[str, Any]:
    path = Path(item.get("path", ""))
    exists = path.is_dir()
    git_root = _git_root(path) if exists else None
    origin = _origin(path) if git_root == path.resolve() else None
    branch = _branch(path) if git_root == path.resolve() else None
    return {
        "id": item.get("id"),
        "name": _redact_secret_text(str(item.get("name") or path.name)),
        "path": _redact_secret_text(str(path)),
        "exists": exists,
        "is_git_repository": git_root == path.resolve() if exists else False,
        "inside_larger_repository": bool(git_root and git_root != path.resolve()) if exists else False,
        "branch": _redact_secret_text(branch) if branch else None,
        "origin": origin,
        "suggested_repo_name": _redact_secret_text(_suggested_repo_name(path)),
        "last_upload_url": _redact_secret_text(str(item.get("last_upload_url"))) if item.get("last_upload_url") else None,
    }


def list_projects() -> dict[str, Any]:
    registry = _load_registry()
    projects = [_project_summary(item) for item in registry["projects"]]
    try:
        owner = github_owner()
        auth = {"connected": True, "owner": owner}
    except UploadError as exc:
        auth = {"connected": False, "error": str(exc)}
    return {"projects": projects, "github": auth, "default_visibility": "private"}


def _project_by_id(project_id: str) -> tuple[dict[str, Any], Path]:
    registry = _load_registry()
    item = next((entry for entry in registry["projects"] if entry.get("id") == project_id), None)
    if not item:
        raise UploadError("没有找到这个项目；请刷新项目列表。")
    path = _validate_project_path(str(item.get("path", "")))
    return item, path


def github_owner() -> str:
    gh = _gh_executable()
    status = run_command([gh, "auth", "status"], check=False, timeout=30)
    if status.returncode != 0:
        raise UploadError("GitHub 尚未登录。请先在 Codex 中完成 GitHub 登录。")
    result = run_command([gh, "api", "user", "--jq", ".login"], timeout=30)
    owner = result.stdout.strip()
    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})", owner):
        raise UploadError("无法确认当前 GitHub 登录账号。")
    return owner


def _validate_repo_name(repo_name: str) -> str:
    value = repo_name.strip()
    if not (1 <= len(value) <= 100) or value in {".", ".."}:
        raise UploadError("GitHub 仓库名长度必须为 1–100 个字符。")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", value):
        raise UploadError("仓库名只能包含字母、数字、连字符、下划线和句点。")
    if _embedded_secret_rule(value):
        raise UploadError("仓库名看起来包含敏感凭据；请先更换仓库名并轮换该凭据。")
    return value


def _new_repo_files(path: Path) -> tuple[list[str], list[str], list[str]]:
    files: list[str] = []
    symlinks: list[str] = []
    nested_repos: list[str] = []
    bare_directory_cache: dict[Path, bool] = {}
    with tempfile.TemporaryDirectory(prefix="codex-github-uploader-") as temporary:
        temp_root = Path(temporary)
        empty_template = temp_root / "empty-template"
        empty_template.mkdir()
        repository = temp_root / "repository"
        run_command(
            [
                _git_executable(),
                "--no-replace-objects",
                "--no-lazy-fetch",
                "-c",
                "maintenance.auto=false",
                "-c",
                "gc.auto=0",
                "init",
                "--quiet",
                f"--template={empty_template}",
                "-b",
                "main",
                str(repository),
            ],
            env_overrides=ISOLATED_GIT_CONFIG_ENV,
            timeout=60,
        )
        listed = run_command(
            [
                _git_executable(),
                "--no-replace-objects",
                "--no-lazy-fetch",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.attributesFile=/dev/null",
                "-c",
                "core.excludesFile=/dev/null",
                "-c",
                "maintenance.auto=false",
                "-c",
                "gc.auto=0",
                f"--git-dir={repository / '.git'}",
                f"--work-tree={path}",
                "ls-files",
                "--others",
                "--exclude-standard",
                "-z",
            ],
            env_overrides=ISOLATED_GIT_CONFIG_ENV,
            timeout=180,
        )
    for entry in listed.stdout.split("\0"):
        relative = entry.rstrip("/")
        if not relative:
            continue
        candidate = path / relative
        if candidate.is_symlink():
            symlinks.append(relative)
            files.append(relative)
        elif candidate.is_dir():
            if (candidate / ".git").exists():
                nested_repos.append(relative)
        else:
            files.append(relative)
            current = candidate.parent
            while current != path and path in current.parents:
                if current not in bare_directory_cache:
                    bare_directory_cache[current] = _looks_like_bare_git_dir(current)
                looks_bare = bare_directory_cache[current]
                if looks_bare:
                    nested_repos.append(current.relative_to(path).as_posix())
                    break
                current = current.parent
        if len(files) > MAX_FILES:
            break
    return sorted(set(files)), sorted(set(symlinks)), sorted(set(nested_repos))


def _git_files(
    path: Path,
) -> tuple[list[str], list[str], list[tuple[str, str]], dict[str, str], dict[str, tuple[str, str]]]:
    result = run_command(
        _git_command(path, "ls-files", "-co", "--exclude-standard", "-z"),
        timeout=120,
    )
    files = sorted({entry for entry in result.stdout.split("\0") if entry})
    staged = run_command(
        _git_command(path, "ls-files", "--stage", "-z"),
        timeout=120,
    )
    gitlinks: list[str] = []
    index_modes: dict[str, str] = {}
    index_entries: dict[str, tuple[str, str]] = {}
    for entry in staged.stdout.split("\0"):
        if not entry:
            continue
        if "\t" not in entry:
            raise UploadError("Git 索引清单格式异常；上传已停止。")
        metadata, relative = entry.split("\t", 1)
        fields = metadata.split(" ")
        if len(fields) != 3:
            raise UploadError("Git 索引清单格式异常；上传已停止。")
        mode, oid, stage = fields
        if not re.fullmatch(r"[0-7]{6}", mode) or not re.fullmatch(r"[0-9a-fA-F]{40,64}", oid):
            raise UploadError("Git 索引对象格式异常；上传已停止。")
        if stage != "0" or relative in index_entries:
            raise UploadError("Git 索引包含未解决冲突或重复路径；上传已停止。")
        index_modes[relative] = mode
        index_entries[relative] = (mode, oid.lower())
        if mode == "160000":
            gitlinks.append(relative)
    flags = run_command(
        _git_command(path, "ls-files", "-v", "-z"),
        timeout=120,
    )
    index_flags: list[tuple[str, str]] = []
    for entry in flags.stdout.split("\0"):
        if len(entry) < 3 or entry[1] != " ":
            continue
        tag, relative = entry[0], entry[2:]
        if tag.islower():
            index_flags.append(("assume_unchanged", relative))
        elif tag == "S":
            index_flags.append(("skip_worktree", relative))
    nested = set(gitlinks)
    for relative in files:
        candidate = path / relative.rstrip("/")
        if candidate.is_dir() and (candidate / ".git").exists():
            nested.add(candidate.relative_to(path).as_posix())
            continue
        current = candidate.parent
        while current != path and path in current.parents:
            if (current / ".git").exists():
                nested.add(current.relative_to(path).as_posix())
                break
            current = current.parent
    return files, sorted(nested), sorted(set(index_flags)), index_modes, index_entries


def _index_head_issues(path: Path, head: str, index_entries: dict[str, tuple[str, str]]) -> list[dict[str, Any]]:
    result = run_command(
        _git_command(path, "ls-tree", "-r", "-z", "--full-tree", head),
        check=False,
        timeout=180,
    )
    if result.returncode != 0:
        return [_issue("block", "head_tree_unreadable", "无法完整读取 HEAD 文件树；上传已停止。")]
    head_entries: dict[str, tuple[str, str]] = {}
    for entry in result.stdout.split("\0"):
        if not entry:
            continue
        if "\t" not in entry:
            return [_issue("block", "head_tree_unreadable", "HEAD 文件树格式异常；上传已停止。")]
        metadata, relative = entry.split("\t", 1)
        fields = metadata.split(" ")
        if len(fields) != 3:
            return [_issue("block", "head_tree_unreadable", "HEAD 文件树格式异常；上传已停止。")]
        mode, object_type, oid = fields
        if (
            not re.fullmatch(r"[0-7]{6}", mode)
            or object_type not in {"blob", "commit"}
            or not re.fullmatch(r"[0-9a-fA-F]{40,64}", oid)
            or relative in head_entries
        ):
            return [_issue("block", "head_tree_unreadable", "HEAD 文件树包含异常对象；上传已停止。")]
        head_entries[relative] = (mode, oid.lower())
    if head_entries != index_entries:
        return [
            _issue(
                "block",
                "index_head_mismatch",
                "Git 索引与 HEAD 的文件树不完全一致；请先提交或恢复暂存变更。",
            )
        ]
    return []


def _git_object_format(path: Path) -> str:
    result = run_command(
        _git_command(path, "rev-parse", "--show-object-format"),
        check=False,
        timeout=30,
    )
    value = result.stdout.strip().lower()
    if result.returncode != 0 or value not in {"sha1", "sha256"}:
        raise UploadError("无法确认 Git 对象格式；上传已停止。")
    return value


def _is_shallow_repository(path: Path) -> bool:
    result = run_command(
        _git_command(path, "rev-parse", "--is-shallow-repository"),
        check=False,
        timeout=30,
    )
    value = result.stdout.strip().lower()
    if result.returncode != 0 or value not in {"true", "false"}:
        raise UploadError("无法确认仓库历史是否完整；上传已停止。")
    return value == "true"


def _commit_is_root(path: Path, oid: str) -> bool:
    metadata = run_command(
        _git_command(path, "cat-file", "--batch-check=%(objecttype) %(objectsize)"),
        input_text=f"{oid}\n",
        check=False,
        timeout=30,
    )
    fields = metadata.stdout.strip().split()
    if metadata.returncode != 0 or len(fields) != 2 or fields[0] != "commit":
        return False
    try:
        size = int(fields[1])
    except ValueError:
        return False
    if size < 1 or size > MAX_HISTORY_BLOB_SCAN_BYTES:
        return False
    try:
        data = _read_history_object(path, oid, "commit", size, MAX_HISTORY_BLOB_SCAN_BYTES)
    except UploadError:
        return False
    headers = data.split(b"\n\n", 1)[0].splitlines()
    return not any(line.startswith(b"parent ") for line in headers)


def _blob_oid(data: bytes, object_format: str) -> str:
    digest = hashlib.new(object_format)
    digest.update(f"blob {len(data)}\0".encode("ascii"))
    digest.update(data)
    return digest.hexdigest()


def _worktree_index_issues(
    path: Path,
    index_entries: dict[str, tuple[str, str]],
    *,
    allow_git_hashing: bool,
) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    regular_paths: list[str] = []
    try:
        object_format = _git_object_format(path)
    except UploadError:
        return [_issue("block", "object_format_unreadable", "无法确认 Git 对象格式；上传已停止。")]

    for relative, (mode, expected_oid) in index_entries.items():
        candidate = path / relative
        try:
            info = candidate.lstat()
        except OSError:
            issues.append(_issue("block", "worktree_index_mismatch", "工作区文件与已确认提交不一致。", relative))
            continue
        if mode == "120000":
            if not stat.S_ISLNK(info.st_mode):
                issues.append(_issue("block", "worktree_index_mismatch", "工作区文件类型与 Git 索引不一致。", relative))
                continue
            try:
                actual_oid = _blob_oid(os.fsencode(os.readlink(candidate)), object_format)
            except OSError:
                issues.append(_issue("block", "worktree_index_mismatch", "无法读取工作区符号链接。", relative))
                continue
            if actual_oid != expected_oid:
                issues.append(_issue("block", "worktree_index_mismatch", "工作区符号链接与已确认提交不一致。", relative))
            continue
        if mode == "160000" or not stat.S_ISREG(info.st_mode):
            issues.append(_issue("block", "worktree_index_mismatch", "工作区文件类型与 Git 索引不一致。", relative))
            continue
        if "\n" in relative or "\r" in relative:
            issues.append(_issue("block", "unsupported_filename", "文件名包含换行符，无法安全核对待推送内容。", relative))
            continue
        regular_paths.append(relative)

    if regular_paths and allow_git_hashing:
        result = run_command(
            _git_command(path, "hash-object", "--stdin-paths"),
            input_text="".join(f"{relative}\n" for relative in regular_paths),
            check=False,
            timeout=600,
        )
        hashes = result.stdout.splitlines()
        if result.returncode != 0 or len(hashes) != len(regular_paths):
            issues.append(_issue("block", "worktree_hash_failed", "无法逐文件核对工作区与 Git 索引；上传已停止。"))
        else:
            for relative, actual_oid in zip(regular_paths, hashes, strict=True):
                expected_oid = index_entries[relative][1]
                if not re.fullmatch(r"[0-9a-fA-F]{40,64}", actual_oid) or actual_oid.lower() != expected_oid:
                    issues.append(
                        _issue(
                            "block",
                            "worktree_index_mismatch",
                            "工作区文件内容与已确认提交不一致。",
                            relative,
                        )
                    )
    elif regular_paths:
        issues.append(_issue("block", "worktree_hash_unsafe", "仓库配置可能执行外部程序，无法安全核对工作区内容。"))
    return issues


def _path_secret_rule(relative: str) -> str | None:
    path = Path(relative)
    name = path.name.lower()
    if name == ".env" or name.startswith(".env."):
        return "environment_file"
    if name in SENSITIVE_EXACT_NAMES:
        return "credential_file"
    if path.suffix.lower() in SENSITIVE_SUFFIXES:
        return "private_key_or_certificate"
    if name == "credentials":
        return "aws_credentials"
    return None


def _embedded_secret_rule(text: str) -> str | None:
    for code, pattern in SECRET_PATTERNS:
        if pattern.search(text):
            return code
    return None


def _contains_git_filter(data: bytes) -> bool:
    text = data.decode("utf-8", errors="replace")
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if re.search(r"(?:^|\s)filter=[^\s]+", stripped):
            return True
    return False


def _attribute_security_issues(path: Path, files: list[str], is_git: bool) -> tuple[list[dict[str, Any]], bool]:
    directories = {path}
    for relative in files:
        current = (path / relative).parent
        while current != path and path in current.parents:
            directories.add(current)
            current = current.parent

    attribute_files: dict[Path, str] = {}
    issues: list[dict[str, Any]] = []
    unsafe = False
    for directory in directories:
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    if entry.name.lower() == ".gitattributes":
                        candidate = Path(entry.path)
                        label = candidate.relative_to(path).as_posix()
                        attribute_files[candidate] = label
        except OSError:
            issues.append(
                _issue(
                    "block",
                    "git_attributes_unreadable",
                    "无法检查可能影响待上传文件的 .gitattributes；上传已停止。",
                    directory.relative_to(path).as_posix() or ".",
                )
            )
            unsafe = True

    if is_git:
        internal = run_command(
            _git_command(path, "rev-parse", "--path-format=absolute", "--git-path", "info/attributes"),
            check=False,
            timeout=30,
        )
        if internal.returncode != 0 or not internal.stdout.strip():
            issues.append(_issue("block", "git_attributes_unreadable", "无法定位仓库本地 attributes；上传已停止。"))
            unsafe = True
        else:
            candidate = Path(internal.stdout.strip())
            try:
                if candidate.exists() or candidate.is_symlink():
                    attribute_files[candidate] = ".git/info/attributes"
            except OSError:
                issues.append(_issue("block", "git_attributes_unreadable", "无法检查仓库本地 attributes；上传已停止。"))
                unsafe = True

    for candidate, label in attribute_files.items():
        try:
            info = candidate.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise OSError("unsafe attributes file type")
            if info.st_size > MAX_ATTRIBUTES_FILE_BYTES:
                issues.append(
                    _issue(
                        "block",
                        "git_attributes_too_large",
                        ".gitattributes 超过安全检查上限；上传已停止。",
                        label,
                    )
                )
                unsafe = True
                continue
            data = candidate.read_bytes()
            if len(data) != info.st_size:
                raise OSError("attributes changed while reading")
        except OSError:
            issues.append(_issue("block", "git_attributes_unreadable", "无法可靠读取 Git attributes；上传已停止。", label))
            unsafe = True
            continue
        if _contains_git_filter(data):
            issues.append(
                _issue(
                    "block",
                    "external_git_filter",
                    "检测到 Git 内容过滤器（包括 Git LFS）；此上传器不会执行过滤器或上传 LFS 对象。",
                    label,
                )
            )
            unsafe = True
    return issues, unsafe


def _issue(severity: str, code: str, message: str, path: str | None = None, line: int | None = None) -> dict[str, Any]:
    value: dict[str, Any] = {"severity": severity, "code": code, "message": message}
    if path:
        value["path"] = _redact_secret_text(path)
    if line:
        value["line"] = line
    return value


def _scan_bytes(data: bytes, relative: str, source: str) -> list[dict[str, Any]]:
    text = data.decode("utf-8", errors="ignore")
    issues: list[dict[str, Any]] = []
    if re.search(r"(?m)^version https://git-lfs\.github\.com/spec/v1\r?$", text):
        issues.append(
            _issue(
                "block",
                f"{source}_git_lfs_pointer",
                "检测到 Git LFS pointer；此上传器不会代替 LFS 上传对象，请先改用普通 Git 文件或另行完成 LFS 上传。",
                relative,
            )
        )
    for code, pattern in SECRET_PATTERNS:
        match = pattern.search(text)
        if match:
            line = text.count("\n", 0, match.start()) + 1
            issues.append(
                _issue(
                    "block",
                    f"{source}_{code}",
                    "检测到可能的敏感凭据；不会显示其内容。请移除、轮换或加入忽略规则后重试。",
                    relative,
                    line,
                )
            )
    if '"type"' in text and SERVICE_ACCOUNT_TYPE_MARKER in text and PRIVATE_KEY_FIELD_MARKER in text:
        issues.append(
            _issue(
                "block",
                f"{source}_service_account",
                "检测到可能的云服务账号凭据；不会显示其内容。",
                relative,
            )
        )
    return issues


def _history_object_inventory(path: Path) -> list[tuple[str, str, int, str]]:
    rev_output = _run_bounded_stdout(
        _git_command(path, "rev-list", "--objects", "--all"),
        max_bytes=MAX_HISTORY_OBJECT_OUTPUT_BYTES,
        timeout=120,
    )
    if not rev_output.strip():
        return []
    object_paths: dict[str, str] = {}
    for line in rev_output.splitlines():
        oid, _, rel = line.partition(" ")
        if oid and oid not in object_paths:
            object_paths[oid] = rel or f"history:{oid[:12]}"
        if len(object_paths) > MAX_HISTORY_OBJECTS:
            raise UploadError("Git 历史对象数量超过安全检查上限；上传已停止。")
    check = run_command(
        _git_command(path, "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"),
        input_text="".join(f"{oid}\n" for oid in object_paths),
        check=False,
        timeout=180,
    )
    if check.returncode != 0:
        raise UploadError("无法完整检查 Git 历史对象；上传已停止。")
    inventory: list[tuple[str, str, int, str]] = []
    lines = check.stdout.splitlines()
    if len(lines) != len(object_paths):
        raise UploadError("Git 历史对象清单不完整；上传已停止。")
    for line in lines:
        fields = line.split(" ", 2)
        if len(fields) != 3:
            raise UploadError("Git 历史中存在无法读取的对象；上传已停止。")
        object_type = fields[1]
        if object_type not in {"blob", "commit", "tag"}:
            continue
        try:
            size = int(fields[2])
        except ValueError as exc:
            raise UploadError("Git 历史对象大小无效；上传已停止。") from exc
        if object_type == "blob":
            label = object_paths.get(fields[0], f"history:{fields[0][:12]}")
        else:
            label = f"{object_type}:{fields[0][:12]}"
        inventory.append((fields[0], object_type, size, label))
    return inventory


def _history_paths(path: Path) -> list[str]:
    output = _run_bounded_stdout(
        _git_command(path, "log", "--all", "-m", "--name-only", "-z", "--no-renames", "--format="),
        max_bytes=MAX_HISTORY_PATH_OUTPUT_BYTES,
        timeout=180,
    )
    entries = [entry for entry in output.split("\0") if entry]
    if len(entries) > MAX_HISTORY_PATHS:
        raise UploadError("Git 历史路径数量超过安全检查上限；上传已停止。")
    return entries


def _read_history_object(path: Path, oid: str, object_type: str, expected_size: int, max_bytes: int) -> bytes:
    if object_type not in {"blob", "commit", "tag"}:
        raise UploadError("Git 历史对象类型无效；上传已停止。")
    command = _git_command(path, "cat-file", object_type, oid)
    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=_command_environment(command),
        timeout=60,
        shell=False,
        check=False,
    )
    if result.returncode != 0 or len(result.stdout) != expected_size or len(result.stdout) > max_bytes:
        raise UploadError("Git 历史中存在无法完整读取的对象；上传已停止。")
    return result.stdout


def _local_git_config_issues(path: Path) -> tuple[list[dict[str, Any]], bool, bool]:
    result = run_command(
        _git_command(path, "config", "--local", "--name-only", "--list"),
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        return [_issue("block", "git_config_failed", "无法可靠检查仓库本地 Git 配置；上传已停止。")], True, True
    names = {line.strip().lower() for line in result.stdout.splitlines() if line.strip()}
    issues: list[dict[str, Any]] = []
    worktree_enabled = run_command(
        _git_command(path, "config", "--local", "--bool", "--get", "extensions.worktreeConfig"),
        check=False,
        timeout=30,
    )
    if worktree_enabled.returncode not in {0, 1}:
        return [_issue("block", "git_config_failed", "无法确认仓库的 worktree 配置；上传已停止。")], True, True
    if worktree_enabled.returncode == 0 and worktree_enabled.stdout.strip().lower() == "true":
        worktree = run_command(
            _git_command(path, "config", "--worktree", "--name-only", "--list"),
            check=False,
            timeout=30,
        )
        if worktree.returncode != 0:
            return [_issue("block", "git_config_failed", "无法可靠检查仓库 worktree 配置；上传已停止。")], True, True
        names.update(line.strip().lower() for line in worktree.stdout.splitlines() if line.strip())

    risky_transport = any(
        name == "core.sshcommand"
        or name == "core.gitproxy"
        or name == "core.alternaterefscommand"
        or name == "core.hookspath"
        or name == "gc.recentobjectshook"
        or name in {"gpg.program", "gpg.ssh.defaultkeycommand", "uploadpack.packobjectshook"}
        or name == "include.path"
        or (name.startswith("includeif.") and name.endswith(".path"))
        or (name.startswith("url.") and (name.endswith(".insteadof") or name.endswith(".pushinsteadof")))
        or (name.startswith("credential.") and name.endswith(".helper"))
        or (name.startswith("diff.") and name.endswith(".command"))
        or (name.startswith("trailer.") and name.endswith(".command"))
        or (
            name.startswith("remote.")
            and name.endswith((".receivepack", ".uploadpack", ".proxy"))
        )
        for name in names
    )
    risky_filter = any(name.startswith("filter.") for name in names)
    if risky_transport or risky_filter:
        issues.append(
            _issue(
                "block",
                "executable_git_config",
                "仓库或 worktree Git 配置包含可执行命令、内容过滤器或传输改写；上传已停止。",
            )
        )
    partial_clone = any(
        name in {"extensions.partialclone", "protocol.ext.allow"}
        or (
            name.startswith("remote.")
            and (
                name.endswith(".promisor")
                or name.endswith(".partialclonefilter")
                or name.endswith(".uploadpack")
            )
        )
        for name in names
    )
    if partial_clone:
        issues.append(
            _issue(
                "block",
                "partial_clone_unsupported",
                "仓库包含 partial-clone、promisor、ext 协议或自定义 upload-pack 配置；请先在可信环境中完整获取所有对象。",
            )
        )
    return issues, partial_clone, risky_transport or risky_filter


def _snapshot(path: Path, include_security_scan: bool = True) -> dict[str, Any]:
    git_root = _git_root(path)
    if git_root is not None and git_root != path:
        raise UploadError(f"项目目录处于更大的 Git 仓库中：{_redact_secret_text(str(git_root))}")
    is_git = git_root == path
    marker_kind = _git_marker_kind(path)
    head = _head(path) if is_git else None
    branch = _branch(path) if is_git else "main"
    origin = _origin(path) if is_git else None
    push_urls = _push_urls(path) if is_git else []
    if is_git:
        files, gitlinks, index_flags, index_modes, index_entries = _git_files(path)
        symlinks: list[str] = []
        nested_repos = gitlinks
    else:
        files, symlinks, nested_repos = _new_repo_files(path)
        index_flags = []
        index_modes = {}
        index_entries = {}

    issues: list[dict[str, Any]] = []
    total_bytes = 0
    current_scanned = 0
    digest = hashlib.sha256()
    noisy_seen: set[str] = set()
    unsafe_partial_clone = False
    unsafe_git_execution = False
    unsafe_shallow_history = False

    if is_git:
        config_issues, unsafe_partial_clone, unsafe_git_execution = _local_git_config_issues(path)
        issues.extend(config_issues)
        try:
            unsafe_shallow_history = _is_shallow_repository(path)
        except UploadError:
            unsafe_shallow_history = True
            issues.append(_issue("block", "shallow_check_failed", "无法确认仓库历史是否完整；上传已停止。"))
        if unsafe_shallow_history:
            issues.append(
                _issue(
                    "block",
                    "shallow_repository_unsupported",
                    "浅克隆仓库可能隐藏将被推送的祖先内容；请先完整获取全部历史。",
                )
            )
    attribute_issues, unsafe_attributes = _attribute_security_issues(path, files, is_git)
    issues.extend(attribute_issues)
    unsafe_git_execution = unsafe_git_execution or unsafe_attributes
    branch_secret_rule = _embedded_secret_rule(branch or "")
    if branch_secret_rule:
        issues.append(
            _issue(
                "block",
                f"branch_{branch_secret_rule}",
                "当前 Git 分支名包含疑似敏感凭据；分支名不会显示，请先重命名。",
            )
        )

    if len(files) > MAX_FILES:
        issues.append(_issue("block", "too_many_files", f"项目超过 {MAX_FILES:,} 个文件，范围可能选得过大。"))
    if not is_git and not (path / ".gitignore").is_file():
        issues.append(_issue("warn", "missing_gitignore", "项目没有 .gitignore；缓存和本地配置也可能被提交。"))
    if marker_kind == "gitfile" and head is None:
        issues.append(
            _issue(
                "block",
                "linked_gitdir_without_head",
                "此项目使用项目外 Git 元数据且尚无提交；为避免在所选目录外写入，上传已停止。",
            )
        )
    if is_git:
        replace_refs = run_command(
            _git_command(path, "for-each-ref", "--format=%(refname)", "refs/replace"),
            check=False,
            timeout=30,
        )
        if replace_refs.returncode != 0:
            issues.append(_issue("block", "replace_ref_check_failed", "无法检查 Git replace 引用；上传已停止。"))
        elif replace_refs.stdout.strip():
            issues.append(
                _issue(
                    "block",
                    "git_replace_refs",
                    "仓库包含 Git replace 引用，可能让工作区与真实推送对象不一致；请先移除后重试。",
                )
            )
        graft_path_result = run_command(
            _git_command(path, "rev-parse", "--git-path", "info/grafts"),
            check=False,
            timeout=30,
        )
        if graft_path_result.returncode != 0:
            issues.append(_issue("block", "graft_check_failed", "无法检查旧式 Git grafts；上传已停止。"))
        elif graft_path_result.stdout.strip():
            graft_path = Path(graft_path_result.stdout.strip())
            if not graft_path.is_absolute():
                graft_path = path / graft_path
            try:
                if graft_path.is_file() and graft_path.stat().st_size:
                    issues.append(
                        _issue(
                            "block",
                            "git_grafts",
                            "仓库包含旧式 Git grafts，可能让历史扫描与真实推送对象不一致；请先移除后重试。",
                        )
                    )
            except OSError:
                issues.append(_issue("block", "graft_check_failed", "无法检查旧式 Git grafts；上传已停止。"))
    for nested in nested_repos:
        issues.append(_issue("block", "nested_repository", "检测到嵌套 Git 仓库或 submodule；请先明确处理方式。", nested))
    for flag, relative in index_flags:
        label = "assume-unchanged" if flag == "assume_unchanged" else "skip-worktree"
        issues.append(
            _issue(
                "block",
                "hidden_index_state",
                f"Git 索引为此文件设置了 {label}，可能隐藏当前修改；请清除该标记后重试。",
                relative,
            )
        )
    for link in symlinks[:20]:
        issues.append(_issue("warn", "symlink", "检测到符号链接；Git 只会记录链接本身。", link))

    for relative in files[: MAX_FILES + 1]:
        candidate = path / relative
        if "\n" in relative or "\r" in relative:
            issues.append(_issue("block", "unsupported_filename", "文件名包含换行符，无法安全核对待上传内容。", relative))
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            if is_git:
                digest.update(f"D\0{relative}\n".encode())
                continue
            issues.append(_issue("block", "unreadable_file", "文件在预检时消失。", relative))
            continue
        except OSError:
            issues.append(_issue("block", "unreadable_file", "文件在预检时无法读取。", relative))
            continue
        if stat.S_ISLNK(info.st_mode):
            try:
                link_target = os.readlink(candidate)
            except OSError:
                issues.append(_issue("block", "unreadable_file", "符号链接在预检时无法读取。", relative))
                continue
            git_mode = "120000"
            digest.update(f"L\0{relative}\0{git_mode}\0{link_target}\n".encode())
            if relative in index_modes and index_modes[relative] != git_mode:
                issues.append(
                    _issue(
                        "block",
                        "git_mode_mismatch",
                        "当前文件类型或可执行位与 Git 索引不一致；请更新索引后重试。",
                        relative,
                    )
                )
            continue
        if not stat.S_ISREG(info.st_mode):
            continue
        size = info.st_size
        git_mode = "100755" if info.st_mode & 0o111 else "100644"
        total_bytes += size
        digest.update(f"F\0{relative}\0{git_mode}\0{size}\0{info.st_mtime_ns}\n".encode())
        if relative in index_modes and index_modes[relative] != git_mode:
            issues.append(
                _issue(
                    "block",
                    "git_mode_mismatch",
                    "当前文件类型或可执行位与 Git 索引不一致；请更新索引后重试。",
                    relative,
                )
            )
        path_rule = _path_secret_rule(relative)
        if path_rule:
            issues.append(
                _issue(
                    "block",
                    path_rule,
                    "文件名表明它可能包含凭据；请移除或确保它被 Git 忽略。",
                    relative,
                )
            )
        embedded_path_rule = _embedded_secret_rule(relative)
        if embedded_path_rule:
            issues.append(
                _issue(
                    "block",
                    f"current_path_{embedded_path_rule}",
                    "文件名本身包含疑似敏感凭据；路径已脱敏，请重命名并轮换凭据后重试。",
                    relative,
                )
            )
        if size >= BLOCK_FILE_BYTES:
            issues.append(_issue("block", "file_too_large", "单个文件达到或超过 GitHub 的 100 MiB 限制。", relative))
        elif size >= WARN_FILE_BYTES:
            issues.append(_issue("warn", "large_file", "单个文件超过 50 MiB，建议使用 Git LFS。", relative))
        for part in Path(relative).parts[:-1]:
            if part.lower() in NOISY_PARTS and part.lower() not in noisy_seen:
                noisy_seen.add(part.lower())
                issues.append(_issue("warn", "generated_or_data_directory", "检测到常见缓存、构建或数据目录；请确认确实需要上传。", relative))
        if include_security_scan and current_scanned < MAX_CURRENT_SCAN_BYTES:
            read_size = min(size, MAX_CURRENT_SCAN_BYTES - current_scanned)
            try:
                with candidate.open("rb") as handle:
                    data = handle.read(read_size)
                current_scanned += len(data)
                digest.update(hashlib.sha256(data).digest())
                if len(data) != read_size:
                    issues.append(_issue("block", "file_changed_during_scan", "文件在安全扫描期间发生变化；请重新预检。", relative))
                issues.extend(_scan_bytes(data, relative, "current"))
                if Path(relative).name.lower() == ".gitattributes" and _contains_git_filter(data):
                    issues.append(
                        _issue(
                            "block",
                            "external_git_filter",
                            "检测到 Git 内容过滤器（包括 Git LFS）；此上传器不执行过滤器或上传 LFS 对象。",
                            relative,
                        )
                    )
            except OSError:
                issues.append(_issue("block", "unreadable_file", "文件在敏感信息扫描时无法读取。", relative))

    if total_bytes >= BLOCK_TOTAL_BYTES:
        issues.append(_issue("block", "project_too_large", "待上传文件总量达到或超过 2 GiB；请先拆分项目或配置 Git LFS。"))
    if include_security_scan and total_bytes > current_scanned:
        issues.append(_issue("block", "current_scan_incomplete", "项目内容超过安全扫描上限，不能确认所有待上传文件均已检查。"))

    history_blob_count = 0
    history_object_count = 0
    history_bytes = 0
    if include_security_scan and is_git and head and not unsafe_partial_clone and not unsafe_shallow_history:
        seen_sensitive_history_paths: set[tuple[str, str]] = set()
        for relative in _history_paths(path):
            path_rule = _path_secret_rule(relative)
            key = (path_rule or "", relative)
            if path_rule and key not in seen_sensitive_history_paths:
                seen_sensitive_history_paths.add(key)
                issues.append(
                    _issue(
                        "block",
                        f"history_{path_rule}",
                        "Git 历史中存在疑似凭据文件；需要先清理历史。",
                        relative,
                    )
                )
            embedded_path_rule = _embedded_secret_rule(relative)
            embedded_key = (f"embedded:{embedded_path_rule or ''}", relative)
            if embedded_path_rule and embedded_key not in seen_sensitive_history_paths:
                seen_sensitive_history_paths.add(embedded_key)
                issues.append(
                    _issue(
                        "block",
                        f"history_path_{embedded_path_rule}",
                        "Git 历史文件名包含疑似敏感凭据；路径已脱敏，需要先清理历史。",
                        relative,
                    )
                )
        inventory = _history_object_inventory(path)
        history_object_count = len(inventory)
        history_blob_count = sum(1 for _, object_type, _, _ in inventory if object_type == "blob")
        for oid, object_type, size, relative in inventory:
            if object_type == "blob":
                path_rule = _path_secret_rule(relative)
                key = (path_rule or "", relative)
                if path_rule and key not in seen_sensitive_history_paths:
                    seen_sensitive_history_paths.add(key)
                    issues.append(_issue("block", f"history_{path_rule}", "Git 历史中存在疑似凭据文件；需要先清理历史。", relative))
                if size >= BLOCK_FILE_BYTES:
                    issues.append(_issue("block", "history_file_too_large", "Git 历史中有达到或超过 100 MiB 的文件。", relative))
                elif size >= WARN_FILE_BYTES:
                    issues.append(_issue("warn", "history_large_file", "Git 历史中有超过 50 MiB 的文件。", relative))
            if size > MAX_HISTORY_BLOB_SCAN_BYTES:
                issues.append(
                    _issue(
                        "block",
                        "history_object_scan_incomplete",
                        "Git 历史中的这个对象过大，无法完整检查敏感信息。",
                        relative,
                    )
                )
                continue
            if history_bytes + size > MAX_HISTORY_SCAN_BYTES:
                issues.append(_issue("block", "history_scan_incomplete", "Git 历史内容超过安全扫描上限，无法完整检查敏感信息。"))
                break
            data = _read_history_object(path, oid, object_type, size, MAX_HISTORY_BLOB_SCAN_BYTES)
            history_bytes += len(data)
            issues.extend(_scan_bytes(data, relative, "history"))

    if is_git and head:
        issues.extend(_index_head_issues(path, head, index_entries))
        issues.extend(
            _worktree_index_issues(
                path,
                index_entries,
                allow_git_hashing=not unsafe_git_execution,
            )
        )

    status = ""
    status_ok = True
    changes = {"staged": 0, "unstaged": 0, "untracked": 0, "deleted": 0}
    if is_git and not unsafe_git_execution:
        status_result = run_command(
            _git_command(path, "status", "--porcelain=v2", "--untracked-files=all"),
            check=False,
            timeout=120,
        )
        status_ok = status_result.returncode == 0
        if not status_ok:
            issues.append(_issue("block", "git_status_failed", "无法可靠读取 Git 工作区状态；上传已停止。"))
        status = status_result.stdout
        for line in status.splitlines():
            if line.startswith("? "):
                changes["untracked"] += 1
                continue
            if line[:2] not in {"1 ", "2 ", "u "}:
                continue
            fields = line.split(" ")
            xy = fields[1] if len(fields) > 1 else ".."
            if len(xy) >= 2:
                if xy[0] != ".":
                    changes["staged"] += 1
                if xy[1] != ".":
                    changes["unstaged"] += 1
                if "D" in xy:
                    changes["deleted"] += 1
    elif is_git:
        status_ok = False
        issues.append(_issue("block", "git_status_unsafe", "仓库配置可能执行外部程序，未运行 Git status；上传已停止。"))
    else:
        changes["untracked"] = len(files)
    content_fingerprint = digest.hexdigest()
    digest.update(status.encode("utf-8", errors="replace"))
    digest.update((head or "").encode())
    digest.update((branch or "").encode())
    digest.update((origin or "").encode())
    for push_url in push_urls:
        digest.update(push_url.encode())

    final_head = _head(path) if is_git else None
    final_branch = _branch(path) if is_git else "main"
    final_origin = _origin(path) if is_git else None
    final_push_urls = _push_urls(path) if is_git else []
    if (final_head, final_branch, final_origin, final_push_urls) != (head, branch, origin, push_urls):
        issues.append(_issue("block", "repository_changed_during_scan", "Git 仓库在预检期间发生变化；请重新预检。"))

    unique: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for issue in issues:
        key = (issue.get("severity"), issue.get("code"), issue.get("path"), issue.get("line"))
        if key not in seen:
            seen.add(key)
            unique.append(issue)

    return {
        "fingerprint": digest.hexdigest(),
        "content_fingerprint": content_fingerprint,
        "is_git_repository": is_git,
        "branch": branch,
        "head": head,
        "origin": origin,
        "push_urls": push_urls,
        "file_count": len(files),
        "total_bytes": total_bytes,
        "history_blob_count": history_blob_count,
        "history_object_count": history_object_count,
        "issues": unique[:200],
        "issue_count": len(unique),
        "blocking_issue_count": sum(1 for issue in unique if issue["severity"] == "block"),
        "warning_count": sum(1 for issue in unique if issue["severity"] == "warn"),
        "changes": changes,
        "is_clean": status_ok and not bool(status),
    }


def _repo_view(owner: str, repo: str) -> dict[str, Any] | None:
    result = run_command(
        [_gh_executable(), "api", f"repos/{owner}/{repo}"],
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        diagnostic = f"{result.stdout}\n{result.stderr}"
        if re.search(r"(?:HTTP(?:/\S+)?\s+404|\(HTTP 404\))", diagnostic):
            return None
        raise UploadError(f"无法确认 GitHub 仓库是否存在：{_safe_error(result.stderr or result.stdout)}")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise UploadError("GitHub 返回了无法解析的仓库信息；请稍后重试。") from exc
    if not isinstance(value, dict) or not value.get("full_name") or not value.get("html_url"):
        raise UploadError("GitHub 返回的仓库信息不完整；请稍后重试。")
    expected = f"{owner}/{repo}".lower()
    html_url = str(value["html_url"])
    parsed_url = urlsplit(html_url)
    if str(value["full_name"]).lower() != expected:
        raise UploadError("GitHub 返回的仓库身份与请求目标不一致；请稍后重试。")
    if parsed_url.scheme != "https" or parsed_url.hostname != "github.com":
        raise UploadError("GitHub 返回的仓库链接无效；请稍后重试。")
    return {
        "nameWithOwner": value["full_name"],
        "visibility": value.get("visibility") or ("private" if value.get("private") else "public"),
        "url": html_url,
    }


def _remote_alignment_issues(origin: str | None, push_urls: list[str], target_slug: str) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    expected = target_slug.lower()
    if not origin:
        if push_urls:
            issues.append(_issue("block", "push_url_conflict", "检测到没有对应 origin 的推送地址；上传已停止。"))
        return issues
    if _github_slug_from_remote(origin) != expected:
        issues.append(
            _issue(
                "block",
                "origin_conflict",
                f"现有 origin 指向其他仓库（{origin}）；插件不会覆盖它。",
            )
        )
    if len(push_urls) != 1:
        issues.append(
            _issue(
                "block",
                "push_url_conflict",
                "origin 的实际推送地址缺失或不唯一；请先修复 remote.origin.pushurl。",
            )
        )
    elif _github_slug_from_remote(push_urls[0]) != expected:
        issues.append(
            _issue(
                "block",
                "push_url_conflict",
                f"origin 的实际推送地址指向其他仓库（{push_urls[0]}）；上传已停止。",
            )
        )
    return issues


def preflight_upload(project_id: str, repo_name: str, visibility: str = "private") -> dict[str, Any]:
    item, path = _project_by_id(project_id)
    repo = _validate_repo_name(repo_name)
    visibility = visibility.strip().lower()
    if visibility not in {"private", "public"}:
        raise UploadError("仓库可见性只能是 private 或 public。")
    owner = github_owner()
    snapshot = _snapshot(path, include_security_scan=True)
    target_slug = f"{owner}/{repo}"
    origin_slug = _github_slug_from_remote(snapshot.get("origin") or "")
    target = _repo_view(owner, repo)
    issues = list(snapshot["issues"])
    issues.extend(_remote_alignment_issues(snapshot.get("origin"), snapshot.get("push_urls", []), target_slug))
    actual_visibility = str(target.get("visibility", "")).lower() if target else None

    if snapshot["is_git_repository"] and snapshot["branch"] is None:
        issues.append(_issue("block", "detached_head", "当前仓库处于 detached HEAD；请先切换或创建分支。"))
    if snapshot["is_git_repository"] and snapshot["head"] is not None and not snapshot["is_clean"]:
        counts = snapshot["changes"]
        issues.append(
            _issue(
                "block",
                "dirty_repository",
                "已有 Git 仓库存在未提交变更；为避免改变你的暂存选择，请先提交或清理后再上传"
                f"（暂存 {counts['staged']}、未暂存 {counts['unstaged']}、未跟踪 {counts['untracked']}）。",
            )
        )
    if snapshot["head"] is None and snapshot["file_count"] == 0:
        issues.append(_issue("block", "empty_project", "项目没有可提交的文件。"))
    if target is not None and origin_slug != target_slug.lower():
        issues.append(_issue("block", "target_exists", f"GitHub 上已存在 {target_slug}，但本地 origin 未与它绑定。"))
    if target is not None and actual_visibility not in {"private", "public"}:
        issues.append(_issue("block", "unknown_target_visibility", "无法确认现有 GitHub 仓库的实际可见性。"))
    elif target is not None and actual_visibility != visibility:
        issues.append(
            _issue(
                "block",
                "visibility_mismatch",
                f"现有仓库实际为 {actual_visibility}，与本次计划的 {visibility} 不一致；请按实际可见性重新预检。",
            )
        )
    if visibility == "public":
        issues.append(_issue("warn", "public_repository", "这是公开仓库；任何人都能看到上传内容。"))

    blocking = sum(1 for issue in issues if issue["severity"] == "block")
    warnings = sum(1 for issue in issues if issue["severity"] == "warn")
    plan_id = secrets.token_urlsafe(24)
    plan = {
        "id": plan_id,
        "project_id": project_id,
        "project_name": item.get("name") or path.name,
        "path": str(path),
        "owner": owner,
        "repo_name": repo,
        "target": target_slug,
        "visibility": visibility,
        "fingerprint": snapshot["fingerprint"],
        "content_fingerprint": snapshot["content_fingerprint"],
        "head": snapshot["head"],
        "branch": snapshot["branch"],
        "created_at": time.time(),
        "expires_at": time.time() + PLAN_TTL_SECONDS,
        "used": False,
        "blocking_issue_count": blocking,
    }
    with _state_lock():
        plans = _load_plans()
        plans["plans"][plan_id] = plan
        _write_json(PLANS_PATH, plans)

    return {
        "plan_id": plan_id,
        "ready": blocking == 0,
        "expires_in_seconds": PLAN_TTL_SECONDS,
        "project": {
            "id": project_id,
            "name": _redact_secret_text(str(plan["project_name"])),
            "path": _redact_secret_text(str(path)),
        },
        "repository": {
            "owner": owner,
            "name": repo,
            "name_with_owner": target_slug,
            "visibility": visibility,
            "actual_visibility": actual_visibility,
            "already_exists": target is not None,
            "url": target.get("url") if target else f"https://github.com/{target_slug}",
        },
        "git": {
            "is_git_repository": snapshot["is_git_repository"],
            "branch": _redact_secret_text(snapshot["branch"]) if snapshot["branch"] else None,
            "head": snapshot["head"],
            "origin": snapshot["origin"],
            "push_urls": snapshot["push_urls"],
        },
        "files": {
            "count": snapshot["file_count"],
            "total_bytes": snapshot["total_bytes"],
            "history_blob_count": snapshot["history_blob_count"],
        },
        "issues": issues[:200],
        "issue_count": len(issues),
        "blocking_issue_count": blocking,
        "warning_count": warnings,
        "confirmation_label": (
            f"上传到 {target_slug}（{'私有' if visibility == 'private' else '公开'}）"
            if blocking == 0
            else "请先处理阻止项"
        ),
        "public_confirmation_required": visibility == "public",
        "changes": snapshot["changes"],
    }


def _validate_plan_record(plan: Any) -> dict[str, Any]:
    if not isinstance(plan, dict):
        raise UploadError("上传计划不存在或已过期；请重新预检。")
    if plan.get("used"):
        raise UploadError("这个一次性上传计划已经使用；请重新预检。")
    if time.time() > float(plan.get("expires_at", 0)):
        raise UploadError("上传计划已过期；请重新预检。")
    if int(plan.get("blocking_issue_count", 1)):
        raise UploadError("预检存在阻止项，不能上传。")
    return plan


def _read_plan(plan_id: str) -> dict[str, Any]:
    with _state_lock():
        return dict(_validate_plan_record(_load_plans()["plans"].get(plan_id)))


def _claim_plan(plan_id: str) -> None:
    with _state_lock():
        plans = _load_plans()
        plan = _validate_plan_record(plans["plans"].get(plan_id))
        plan["used"] = True
        plan["used_at"] = time.time()
        _write_json(PLANS_PATH, plans)


def execute_upload(plan_id: str, confirm_public_repository: str = "") -> dict[str, Any]:
    plan = _read_plan(plan_id)
    if plan.get("visibility") == "public" and confirm_public_repository != plan.get("target"):
        raise UploadError(f"公开上传需要再次输入完整仓库名：{plan.get('target')}")

    item, path = _project_by_id(str(plan.get("project_id", "")))
    current = _snapshot(path, include_security_scan=True)
    if current["fingerprint"] != plan.get("fingerprint"):
        raise UploadError("项目内容或 Git 状态在预检后发生了变化；请重新预检。")
    if current["blocking_issue_count"]:
        raise UploadError("重新检查发现阻止项；请重新预检。")

    owner = github_owner()
    if owner != plan.get("owner"):
        raise UploadError("当前 GitHub 登录账号已变化；请重新预检。")
    repo = _validate_repo_name(str(plan.get("repo_name", "")))
    target_slug = f"{owner}/{repo}"
    if target_slug != plan.get("target"):
        raise UploadError("上传目标与预检计划不一致；请重新预检。")
    origin = current.get("origin")
    origin_slug = _github_slug_from_remote(origin or "")
    remote_issues = _remote_alignment_issues(origin, current.get("push_urls", []), target_slug)
    if remote_issues:
        raise UploadError(remote_issues[0]["message"])
    target = _repo_view(owner, repo)
    if target is not None and origin_slug != target_slug.lower():
        raise UploadError("目标仓库已存在但未与本地 origin 绑定；请重新确认仓库。")
    if target is not None and str(target.get("visibility", "")).lower() != plan.get("visibility"):
        raise UploadError("目标仓库的实际可见性与预检计划不一致；请重新预检。")

    _claim_plan(plan_id)
    if os.environ.get("UPLOAD_DRY_RUN") == "1":
        return {"uploaded": False, "dry_run": True, "repository_url": f"https://github.com/{target_slug}"}

    gh = _gh_executable()
    if not current["is_git_repository"]:
        initialized = run_command(
            _git_command(path, "init", "--template=", "-b", "main"),
            check=False,
            timeout=60,
            env_overrides=ISOLATED_GIT_CONFIG_ENV,
        )
        if initialized.returncode != 0:
            run_command(
                _git_command(path, "init", "--template="),
                timeout=60,
                env_overrides=ISOLATED_GIT_CONFIG_ENV,
            )
            run_command(_git_command(path, "branch", "-M", "main"), timeout=60)

    needs_initial_commit = not current["is_git_repository"] or current["head"] is None
    committed = False
    if needs_initial_commit:
        precommit_snapshot = _snapshot(path, include_security_scan=True)
        if precommit_snapshot["head"] is not None:
            raise UploadError("创建初始提交前检测到已有 Git 历史；为避免上传未预检历史，操作已停止。")
        if precommit_snapshot["blocking_issue_count"]:
            raise UploadError("创建初始提交前复检发现阻止项；未创建 GitHub 仓库。")
        if precommit_snapshot["content_fingerprint"] != plan.get("content_fingerprint"):
            raise UploadError("创建初始提交前项目内容发生变化；未创建 GitHub 仓库。")
        if precommit_snapshot["branch"] != plan.get("branch"):
            raise UploadError("创建初始提交前分支发生变化；未创建 GitHub 仓库。")
        run_command(_git_command(path, "add", "-A"), timeout=600)
        staged = run_command(
            _git_command(path, "diff", "--cached", "--quiet", "--no-ext-diff"),
            check=False,
            timeout=120,
        )
        if staged.returncode == 1:
            identity_env = {
                "GIT_AUTHOR_NAME": owner,
                "GIT_COMMITTER_NAME": owner,
                "GIT_AUTHOR_EMAIL": f"{owner}@users.noreply.github.com",
                "GIT_COMMITTER_EMAIL": f"{owner}@users.noreply.github.com",
            }
            run_command(
                _git_command(path, "commit", "-m", "Initial project upload"),
                timeout=600,
                env_overrides=identity_env,
            )
            committed = True
        elif staged.returncode == 0:
            raise UploadError("项目没有可提交的文件；未创建 GitHub 仓库。")
        else:
            raise UploadError("无法确认暂存内容；未创建 GitHub 仓库。")

    push_oid = _head(path)
    validated_branch = _branch(path)
    if not push_oid or not validated_branch:
        raise UploadError("无法固定要上传的提交或分支；请重新预检。")
    if needs_initial_commit:
        if not _commit_is_root(path, push_oid):
            raise UploadError("初始提交意外包含父提交；为避免上传未预检历史，未创建 GitHub 仓库。")
        committed_snapshot = _snapshot(path, include_security_scan=True)
        if committed_snapshot["blocking_issue_count"]:
            raise UploadError("初始提交复检发现阻止项；未创建 GitHub 仓库。")
        if committed_snapshot["content_fingerprint"] != plan.get("content_fingerprint"):
            raise UploadError("提交内容与预检内容不一致；未创建 GitHub 仓库。")
        if committed_snapshot["head"] != push_oid or committed_snapshot["branch"] != validated_branch:
            raise UploadError("Git 提交或分支在复检期间发生变化；未创建 GitHub 仓库。")
        if not committed_snapshot["is_clean"]:
            raise UploadError("初始提交后仍有未提交变更；未创建 GitHub 仓库。")
    else:
        if push_oid != plan.get("head") or validated_branch != plan.get("branch"):
            raise UploadError("Git 提交或分支在预检后发生变化；请重新预检。")

    current_origin = _origin(path)
    current_origin_slug = _github_slug_from_remote(current_origin or "")
    visibility_flag = "--private" if plan.get("visibility") == "private" else "--public"
    safe_push_url = f"git@github.com:{owner}/{repo}.git"
    created = False
    if target is None:
        if current_origin is not None and current_origin_slug != target_slug.lower():
            raise UploadError("创建仓库前检测到 origin 变化；操作已停止。")
        if current_origin is None:
            run_command(_git_command(path, "remote", "add", "origin", safe_push_url), timeout=60)
            current_origin = _origin(path)
            current_origin_slug = _github_slug_from_remote(current_origin or "")
            if current_origin_slug != target_slug.lower():
                raise UploadError("无法确认刚添加的 origin；未创建 GitHub 仓库。")
        run_command([gh, "repo", "create", target_slug, visibility_flag], timeout=180)
        created = True
    elif current_origin_slug != target_slug.lower():
        raise UploadError("目标仓库已存在但 origin 不匹配；操作已停止。")

    verified_origin = _origin(path)
    verified_push_urls = _push_urls(path)
    remote_issues = _remote_alignment_issues(verified_origin, verified_push_urls, target_slug)
    if remote_issues:
        raise UploadError(remote_issues[0]["message"])

    verified_target = _repo_view(owner, repo)
    if verified_target is None:
        raise UploadError("无法确认 GitHub 目标仓库；未执行推送。")
    if str(verified_target.get("visibility", "")).lower() != plan.get("visibility"):
        raise UploadError("目标仓库的实际可见性已变化；未执行推送。")

    if _head(path) != push_oid:
        raise UploadError("本地 HEAD 已变化；为避免上传未确认提交，操作已停止。")
    with _isolated_push_repository(path, push_oid) as (transport_root, transport_git_dir, transport_env):
        run_command(
            _git_push_command(transport_git_dir, safe_push_url, push_oid, validated_branch),
            timeout=1800,
            env_overrides=transport_env,
        )
        _verify_remote_branch(transport_root, safe_push_url, push_oid, validated_branch)

    url = verified_target["url"]
    with _state_lock():
        registry = _load_registry()
        for entry in registry["projects"]:
            if entry.get("id") == item.get("id"):
                entry["last_upload_url"] = url
                entry["last_upload_at"] = int(time.time())
        _write_json(REGISTRY_PATH, registry)
    return {
        "uploaded": True,
        "created_repository": created,
        "created_commit": committed,
        "repository": target_slug,
        "repository_url": url,
        "visibility": plan.get("visibility"),
        "branch": _redact_secret_text(validated_branch),
        "commit_oid": push_oid,
    }


def seed_projects(paths: Iterable[str]) -> dict[str, Any]:
    added: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    for raw in paths:
        try:
            result = register_project(raw)
            if result["registered"]:
                added.append(result["project"])
        except (UploadError, OSError) as exc:
            skipped.append({"path": raw, "reason": str(exc)})
    return {"added": added, "skipped": skipped, "projects": list_projects()["projects"]}
