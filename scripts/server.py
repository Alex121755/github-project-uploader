#!/usr/bin/env python3
"""Dependency-free MCP stdio server for GitHub Project Uploader.

MCP stdio messages are one JSON-RPC object per line. Project inspection and
GitHub operations live in ``uploader_core``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

import uploader_core  # noqa: E402


SERVER_NAME = "github-project-uploader"
SERVER_TITLE = "GitHub 项目上传器"
SERVER_VERSION = "0.1.1"
SERVER_DESCRIPTION = "选择已注册的本地项目，安全预检后上传到当前登录的 GitHub 账号。"
SERVER_INSTRUCTIONS = (
    "默认私有。选择时只调用 render_upload_picker；指定已注册项目时最多 list_projects 一次；"
    "新根目录用 register_project。随后必须 preflight_upload，并在确认完整目标和可见性后才可"
    "execute_upload；绝不返回检测到的密钥值。"
)

HANDSHAKE_PROTOCOL_VERSIONS = frozenset(
    {"2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"}
)
LATEST_HANDSHAKE_PROTOCOL_VERSION = "2025-11-25"

RESOURCE_URI = "ui://github-project-uploader/picker.html"
RESOURCE_MIME = "text/html;profile=mcp-app"
UI_CSP = {
    "connectDomains": [],
    "resourceDomains": ["https://github.com"],
    "frameDomains": [],
    "baseUriDomains": [],
}
UI_META = {
    "ui": {"resourceUri": RESOURCE_URI},
    "ui/resourceUri": RESOURCE_URI,
    "openai/outputTemplate": RESOURCE_URI,
}
RESOURCE_META = {
    "ui": {"prefersBorder": True, "csp": UI_CSP},
    "openai/widgetPrefersBorder": True,
    "openai/widgetDescription": "选择本地项目并安全上传到 GitHub",
    "openai/widgetCSP": {
        "connect_domains": [],
        "resource_domains": ["https://github.com"],
    },
}


def _empty_schema() -> dict[str, Any]:
    return {"type": "object", "properties": {}, "additionalProperties": False}


TOOLS: list[dict[str, Any]] = [
    {
        "name": "list_projects",
        "title": "列出可上传项目",
        "description": "只读列出已注册的本地项目、Git 状态和当前 GitHub 登录账号。",
        "inputSchema": _empty_schema(),
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True},
    },
    {
        "name": "render_upload_picker",
        "title": "打开 GitHub 项目上传器",
        "description": "显示可点击的项目选择与私有仓库上传卡片。用户想选择项目上传到 GitHub 时优先调用。",
        "inputSchema": _empty_schema(),
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True},
        "_meta": UI_META,
    },
    {
        "name": "register_project",
        "title": "添加项目到上传列表",
        "description": "注册一个明确的本地项目根目录，使它出现在项目上传器中。不要注册用户主目录或宽泛父目录。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "项目根目录的绝对路径。"},
                "display_name": {"type": "string", "default": "", "description": "可选显示名称。"},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    {
        "name": "preflight_upload",
        "title": "预检 GitHub 上传",
        "description": (
            "在真正上传前检查项目、敏感凭据、文件大小、Git 历史和远程冲突，"
            "并生成十分钟有效的一次性计划。默认 visibility=private；只有用户明确要求公开时才可使用 public。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string"},
                "repo_name": {"type": "string"},
                "visibility": {"type": "string", "enum": ["private", "public"], "default": "private"},
            },
            "required": ["project_id", "repo_name"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": True},
    },
    {
        "name": "execute_upload",
        "title": "确认并上传到 GitHub",
        "description": (
            "执行已通过预检的一次性上传计划：可能初始化 Git、提交当前项目、创建 GitHub 仓库并推送。"
            "只有在用户已经明确确认卡片中显示的目标仓库和可见性后才能调用。"
            "公开仓库还必须把完整 owner/repo 传入 confirm_public_repository。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "plan_id": {"type": "string"},
                "confirm_public_repository": {"type": "string", "default": ""},
            },
            "required": ["plan_id"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
            "openWorldHint": True,
        },
    },
]


def uploader_ui() -> str:
    return (PLUGIN_ROOT / "assets" / "uploader.html").read_text(encoding="utf-8")


def _text_result(payload: dict[str, Any], message: str) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": message}],
        "structuredContent": payload,
        "isError": False,
    }


def _tool_error(exc: Exception) -> dict[str, Any]:
    message = uploader_core._safe_error(str(exc)) or "上传器发生未知错误。"
    return {
        "content": [{"type": "text", "text": message}],
        "structuredContent": {"ok": False, "error": message},
        "isError": True,
    }


def _required_string(arguments: dict[str, Any], name: str) -> str:
    value = arguments.get(name)
    if not isinstance(value, str) or not value:
        raise uploader_core.UploadError(f"缺少有效参数：{name}")
    return value


def _optional_string(arguments: dict[str, Any], name: str, default: str = "") -> str:
    value = arguments.get(name, default)
    if not isinstance(value, str):
        raise uploader_core.UploadError(f"参数必须是字符串：{name}")
    return value


def _call_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    try:
        if name == "list_projects":
            payload = {"ok": True, **uploader_core.list_projects()}
            auth = payload.get("github", {})
            account = auth.get("owner") if auth.get("connected") else "未连接"
            return _text_result(payload, f"已加载 {len(payload['projects'])} 个项目；GitHub：{account}。")
        if name == "render_upload_picker":
            payload = {"ok": True, "view": "projects", **uploader_core.list_projects()}
            return _text_result(
                payload,
                "已打开 GitHub 项目上传器。若客户端不显示交互卡片，请根据返回的项目列表在对话中选择。",
            )
        if name == "register_project":
            payload = {
                "ok": True,
                **uploader_core.register_project(
                    _required_string(arguments, "path"),
                    _optional_string(arguments, "display_name"),
                ),
            }
            return _text_result(payload, f"项目已加入上传列表：{payload['project']['name']}")
        if name == "preflight_upload":
            payload = {
                "ok": True,
                "view": "preflight",
                **uploader_core.preflight_upload(
                    _required_string(arguments, "project_id"),
                    _required_string(arguments, "repo_name"),
                    _optional_string(arguments, "visibility", "private"),
                ),
            }
            repository = payload["repository"]
            visibility_label = "公开" if repository["visibility"] == "public" else "私有"
            status = "通过，等待确认" if payload["ready"] else "未通过，尚未上传"
            message = (
                f"预检{status}：{repository['name_with_owner']}（{visibility_label}）；"
                f"{payload['files']['count']} 个文件，阻止 {payload['blocking_issue_count']}，"
                f"警告 {payload['warning_count']}。"
            )
            return _text_result(payload, message)
        if name == "execute_upload":
            payload = {
                "ok": True,
                "view": "complete",
                **uploader_core.execute_upload(
                    _required_string(arguments, "plan_id"),
                    _optional_string(arguments, "confirm_public_repository"),
                ),
            }
            if payload.get("dry_run") or payload.get("uploaded") is False:
                return _text_result(payload, f"测试模式完成，未上传：{payload.get('repository_url', '')}")
            return _text_result(payload, f"上传完成：{payload.get('repository_url', '')}")
        raise uploader_core.UploadError("未知工具；请刷新插件后重试。")
    except Exception as exc:
        return _tool_error(exc)


def _initialize(params: dict[str, Any]) -> dict[str, Any]:
    requested = params.get("protocolVersion")
    protocol = (
        requested
        if isinstance(requested, str) and requested in HANDSHAKE_PROTOCOL_VERSIONS
        else LATEST_HANDSHAKE_PROTOCOL_VERSION
    )
    return {
        "protocolVersion": protocol,
        "capabilities": {
            "tools": {"listChanged": False},
            "resources": {"subscribe": False, "listChanged": False},
        },
        "serverInfo": {
            "name": SERVER_NAME,
            "title": SERVER_TITLE,
            "version": SERVER_VERSION,
            "description": SERVER_DESCRIPTION,
        },
        "instructions": SERVER_INSTRUCTIONS,
    }


def _dispatch(method: str, params: dict[str, Any]) -> dict[str, Any]:
    if method == "initialize":
        return _initialize(params)
    if method == "ping":
        return {}
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(name, str) or not isinstance(arguments, dict):
            raise ValueError("Invalid tools/call parameters")
        return _call_tool(name, arguments)
    if method == "resources/list":
        return {
            "resources": [
                {
                    "uri": RESOURCE_URI,
                    "name": "GitHub 项目上传器界面",
                    "title": "GitHub 项目上传器",
                    "description": "选择项目、检查上传计划并确认推送的交互界面。",
                    "mimeType": RESOURCE_MIME,
                    "_meta": RESOURCE_META,
                }
            ]
        }
    if method == "resources/read":
        if params.get("uri") != RESOURCE_URI:
            raise KeyError("Resource not found")
        return {
            "contents": [
                {
                    "uri": RESOURCE_URI,
                    "mimeType": RESOURCE_MIME,
                    "text": uploader_ui(),
                    "_meta": RESOURCE_META,
                }
            ]
        }
    if method == "resources/templates/list":
        return {"resourceTemplates": []}
    if method == "prompts/list":
        return {"prompts": []}
    raise KeyError("Method not found")


def _reply(message_id: Any, *, result: dict[str, Any] | None = None, error: dict[str, Any] | None = None) -> None:
    response: dict[str, Any] = {"jsonrpc": "2.0", "id": message_id}
    if error is not None:
        response["error"] = error
    else:
        response["result"] = result
    sys.stdout.write(json.dumps(response, ensure_ascii=False, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def _serve_line(line: str) -> None:
    try:
        request = json.loads(line)
    except json.JSONDecodeError:
        _reply(None, error={"code": -32700, "message": "Parse error"})
        return
    if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
        message_id = request.get("id") if isinstance(request, dict) else None
        _reply(message_id, error={"code": -32600, "message": "Invalid Request"})
        return
    message_id = request.get("id")
    method = request.get("method")
    if message_id is None:
        return
    if not isinstance(method, str):
        _reply(message_id, error={"code": -32600, "message": "Invalid Request"})
        return
    params = request.get("params", {})
    if not isinstance(params, dict):
        _reply(message_id, error={"code": -32602, "message": "Invalid params"})
        return
    try:
        _reply(message_id, result=_dispatch(method, params))
    except KeyError:
        _reply(message_id, error={"code": -32601, "message": "Method not found"})
    except (TypeError, ValueError):
        _reply(message_id, error={"code": -32602, "message": "Invalid params"})
    except Exception:
        _reply(message_id, error={"code": -32603, "message": "Internal error"})


def main() -> None:
    for line in sys.stdin:
        if line.strip():
            _serve_line(line)


if __name__ == "__main__":
    main()
