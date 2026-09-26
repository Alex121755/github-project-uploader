from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "scripts"))

import server  # noqa: E402


class ServerContractTests(unittest.TestCase):
    def test_preflight_rejects_missing_plugin_root_from_unrelated_cwd(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            unrelated = Path(temporary) / "unrelated-task"
            unrelated.mkdir()
            missing_plugin_root = Path(temporary) / "missing-plugin"
            original_cwd = Path.cwd()
            try:
                os.chdir(unrelated)
                with mock.patch.object(server, "PLUGIN_ROOT", missing_plugin_root), mock.patch.object(
                    server.uploader_core, "preflight_upload"
                ) as preflight:
                    result = server._call_tool(
                        "preflight_upload",
                        {"project_id": "p1", "repo_name": "example", "visibility": "private"},
                    )
            finally:
                os.chdir(original_cwd)
        self.assertTrue(result["isError"])
        self.assertFalse(result["structuredContent"]["ok"])
        preflight.assert_not_called()

    def test_preflight_rejects_existing_plugin_root_from_unrelated_cwd(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            original_cwd = Path.cwd()
            try:
                os.chdir(temporary)
                with mock.patch.object(server.uploader_core, "preflight_upload") as preflight:
                    result = server._call_tool(
                        "preflight_upload",
                        {"project_id": "p1", "repo_name": "example", "visibility": "private"},
                    )
            finally:
                os.chdir(original_cwd)
        self.assertTrue(result["isError"])
        self.assertFalse(result["structuredContent"]["ok"])
        preflight.assert_not_called()

    def test_tool_text_summaries_do_not_duplicate_structured_payloads(self) -> None:
        listed_payload = {
            "projects": [{"id": "p1", "name": "Example", "path": "/private/example"}],
            "github": {"connected": True, "owner": "octocat"},
            "default_visibility": "private",
        }
        with mock.patch.object(server.uploader_core, "list_projects", return_value=listed_payload):
            listed = server._call_tool("list_projects", {})
        listed_text = listed["content"][0]["text"]
        self.assertNotIn("/private/example", listed_text)
        self.assertLess(len(listed_text.encode()), len(json.dumps(listed["structuredContent"]).encode()) // 2)

        preflight_payload = {
            "plan_id": "plan",
            "ready": True,
            "project": {"isolated_subdirectory": True},
            "repository": {
                "name_with_owner": "octocat/example",
                "visibility": "public",
            },
            "files": {"count": 12},
            "blocking_issue_count": 0,
            "warning_count": 1,
            "issues": [{"severity": "warn", "code": "public_repository", "path": "/private/example"}],
        }
        with mock.patch.object(server.uploader_core, "preflight_upload", return_value=preflight_payload):
            preflight = server._call_tool(
                "preflight_upload",
                {"project_id": "p1", "repo_name": "example", "visibility": "public"},
            )
        preflight_text = preflight["content"][0]["text"]
        self.assertIn("octocat/example", preflight_text)
        self.assertIn("隔离子目录", preflight_text)
        self.assertNotIn("/private/example", preflight_text)
        self.assertLess(
            len(preflight_text.encode()),
            len(json.dumps(preflight["structuredContent"]).encode()) // 2,
        )

        self_check_payload = {
            "project": {"name": "Example", "path": "/private/example"},
            "files": {"count": 2},
            "credential_issue_count": 1,
            "credential_findings": [{"code": "current_assigned_secret", "path": "settings.py", "line": 1}],
            "other_issue_count": 0,
            "other_issues": [],
        }
        with mock.patch.object(server.uploader_core, "self_check_project", return_value=self_check_payload):
            checked = server._call_tool("self_check_project", {"project_id": "p1"})
        self.assertEqual(checked["structuredContent"]["view"], "self_check")
        self.assertIn("疑似凭据 1 项", checked["content"][0]["text"])
        self.assertNotIn("/private/example", checked["content"][0]["text"])
        self.assertNotIn("settings.py", checked["content"][0]["text"])

    def test_initialize_negotiates_only_supported_handshake_versions(self) -> None:
        for version in server.HANDSHAKE_PROTOCOL_VERSIONS:
            with self.subTest(version=version):
                self.assertEqual(server._initialize({"protocolVersion": version})["protocolVersion"], version)
        self.assertEqual(
            server._initialize({"protocolVersion": "future-version"})["protocolVersion"],
            server.LATEST_HANDSHAKE_PROTOCOL_VERSION,
        )
        self.assertEqual(
            server._initialize({})["protocolVersion"],
            server.LATEST_HANDSHAKE_PROTOCOL_VERSION,
        )

    def test_ui_resource_returns_raw_mcp_app_html(self) -> None:
        html = server.uploader_ui()
        self.assertIsInstance(html, str)
        self.assertTrue(html.startswith("<!doctype html>"))
        self.assertIn("ui/initialize", html)
        self.assertIn('visibility: "private"', html)
        self.assertIn("公开仓库不会从卡片直接执行", html)
        self.assertIn("测试模式完成，未上传", html)
        self.assertIn('callTool("execute_upload", { plan_id: plan.plan_id }, 1850000)', html)
        self.assertIn("独立子目录 · main", html)
        self.assertIn("不含父仓库历史", html)
        self.assertIn("远程项目已是最新", html)
        self.assertIn("正在检查敏感文件、项目内容与仓库冲突", html)
        self.assertIn('id="selfCheckButton"', html)
        self.assertIn('callTool("self_check_project", { project_id: state.selectedId }', html)
        self.assertIn("radio.disabled = !project.exists;", html)

    def test_ui_resource_metadata_allows_github_link(self) -> None:
        self.assertEqual(server.RESOURCE_MIME, "text/html;profile=mcp-app")
        self.assertIn("https://github.com", server.RESOURCE_META["ui"]["csp"]["resourceDomains"])

    def test_stdio_protocol_contract(self) -> None:
        requests = [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "contract-test", "version": "1"},
                },
            },
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "resources/read",
                "params": {"uri": server.RESOURCE_URI},
            },
        ]
        payload = "".join(json.dumps(item) + "\n" for item in requests)
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        completed = subprocess.run(
            [sys.executable, "scripts/server.py"],
            cwd=PLUGIN_ROOT,
            input=payload,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            timeout=15,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        responses = {item["id"]: item for item in map(json.loads, completed.stdout.splitlines())}
        self.assertEqual(set(responses), {1, 2, 3})
        self.assertEqual(responses[1]["result"]["serverInfo"]["name"], "github-project-uploader")
        tools = responses[2]["result"]["tools"]
        self.assertEqual(len(tools), 6)
        self_check = next(tool for tool in tools if tool["name"] == "self_check_project")
        self.assertTrue(self_check["annotations"]["readOnlyHint"])
        self.assertFalse(self_check["annotations"]["openWorldHint"])
        execute = next(tool for tool in tools if tool["name"] == "execute_upload")
        self.assertTrue(execute["annotations"]["destructiveHint"])
        content = responses[3]["result"]["contents"][0]
        self.assertEqual(content["mimeType"], server.RESOURCE_MIME)
        self.assertTrue(content["text"].startswith("<!doctype html>"))

    def test_public_release_tree_is_self_scannable(self) -> None:
        files, symlinks, nested = server.uploader_core._new_repo_files(PLUGIN_ROOT)
        self.assertFalse(symlinks)
        self.assertFalse(nested)
        self.assertFalse(any(path.startswith("vendor/") for path in files))
        self.assertFalse(any("__pycache__/" in path or path.endswith(".pyc") for path in files))
        issues = []
        for relative in files:
            path = PLUGIN_ROOT / relative
            issues.extend(server.uploader_core._scan_bytes(path.read_bytes(), relative, "current"))
        blockers = [issue for issue in issues if issue["severity"] == "block"]
        self.assertEqual(blockers, [])

    def test_repository_marketplace_and_portable_python_command(self) -> None:
        mcp = json.loads((PLUGIN_ROOT / ".mcp.json").read_text(encoding="utf-8"))
        command = mcp["mcpServers"]["github-project-uploader"]["command"]
        self.assertEqual(command, "python3")
        marketplace = json.loads(
            (PLUGIN_ROOT / ".agents" / "plugins" / "marketplace.json").read_text(encoding="utf-8")
        )
        self.assertEqual(marketplace["name"], "alex121755-tools")
        entry = marketplace["plugins"][0]
        self.assertEqual(entry["name"], "github-project-uploader")
        self.assertEqual(entry["source"]["source"], "url")
        self.assertTrue(entry["source"]["url"].endswith("/github-project-uploader.git"))
        manifest = json.loads((PLUGIN_ROOT / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8"))
        base_version = manifest["version"].split("+", 1)[0]
        self.assertEqual(base_version, server.SERVER_VERSION)
        self.assertIn(f'appInfo: {{ name: "github-project-uploader", version: "{base_version}" }}', server.uploader_ui())


if __name__ == "__main__":
    unittest.main()
