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

import uploader_core as core  # noqa: E402


def synthetic_github_token() -> str:
    """Build a non-live token-shaped fixture without embedding it in this repo."""
    return "gh" + "p_" + "abcdefghijklmnopqrstuvwxyz123456"


def synthetic_secret_assignment() -> str:
    return "API_" + "KEY=" + "example_secret_value_123456789\n"


def synthetic_credential_url(password: str, suffix: str = "github.com\n") -> str:
    return "https:" + "//alice:" + password + "@" + suffix


class UploaderCoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        self.project = self.root / "project"
        self.project.mkdir()
        self.state_patches = [
            mock.patch.object(core, "STATE_DIR", self.state),
            mock.patch.object(core, "REGISTRY_PATH", self.state / "projects.json"),
            mock.patch.object(core, "PLANS_PATH", self.state / "plans.json"),
            mock.patch.object(core, "LOCK_PATH", self.state / "state.lock"),
        ]
        for patch in self.state_patches:
            patch.start()

    def tearDown(self) -> None:
        for patch in reversed(self.state_patches):
            patch.stop()
        self.temp.cleanup()

    def register(self) -> dict:
        return core.register_project(str(self.project))["project"]

    def preflight(self, project_id: str, repo_name: str = "safe-project") -> dict:
        with mock.patch.object(core, "github_owner", return_value="ExampleUser"), mock.patch.object(
            core, "_repo_view", return_value=None
        ):
            return core.preflight_upload(project_id, repo_name)

    def test_register_is_idempotent_and_state_is_private(self) -> None:
        first = core.register_project(str(self.project))
        second = core.register_project(str(self.project))
        self.assertTrue(first["registered"])
        self.assertFalse(second["registered"])
        self.assertEqual(first["project"]["id"], second["project"]["id"])
        self.assertEqual(self.state.joinpath("projects.json").stat().st_mode & 0o777, 0o600)

    def test_self_check_finds_prefixed_api_key_without_github_or_value_exposure(self) -> None:
        (self.project / ".gitignore").write_text("\n", encoding="utf-8")
        secret = "sample" + "SecretValue" * 3
        (self.project / "settings.py").write_text(
            "# local settings\nOPENAI_" + "API_KEY = '" + secret + "'\n",
            encoding="utf-8",
        )
        project = self.register()
        with mock.patch.object(core, "github_owner", side_effect=AssertionError("unexpected GitHub call")), mock.patch.object(
            core, "_repo_view", side_effect=AssertionError("unexpected GitHub call")
        ):
            result = core.self_check_project(project["id"])
        findings = result["credential_findings"]
        self.assertGreaterEqual(result["credential_issue_count"], 1)
        self.assertTrue(any(issue["code"] == "current_assigned_secret" and issue["line"] == 2 for issue in findings))
        self.assertNotIn(secret, json.dumps(result, ensure_ascii=False))
        self.assertFalse(self.state.joinpath("plans.json").exists())

    def test_self_check_finds_quoted_json_api_key(self) -> None:
        (self.project / ".gitignore").write_text("\n", encoding="utf-8")
        secret = "sample" + "JsonConfigValue" * 3
        (self.project / "config.json").write_text(
            '{"provider_' + 'api_key": "' + secret + '"}\n',
            encoding="utf-8",
        )
        project = self.register()
        result = core.self_check_project(project["id"])
        self.assertTrue(any(issue["code"] == "current_assigned_secret" for issue in result["credential_findings"]))
        self.assertNotIn(secret, json.dumps(result, ensure_ascii=False))

    def test_self_check_finds_deleted_secret_in_git_history(self) -> None:
        subprocess.run([core._git_executable(), "-C", str(self.project), "init", "-b", "main"], check=True, capture_output=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.name", "Test"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.email", "test@example.invalid"], check=True)
        secret = "sample" + "HistoricalValue" * 3
        candidate = self.project / "settings.txt"
        candidate.write_text("SERVICE_" + "API_KEY=" + secret + "\n", encoding="utf-8")
        subprocess.run([core._git_executable(), "-C", str(self.project), "add", "settings.txt"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "commit", "-m", "first"], check=True, capture_output=True)
        candidate.write_text("safe\n", encoding="utf-8")
        subprocess.run([core._git_executable(), "-C", str(self.project), "add", "settings.txt"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "commit", "-m", "remove"], check=True, capture_output=True)
        project = self.register()
        with mock.patch.object(core, "github_owner", side_effect=AssertionError("unexpected GitHub call")):
            result = core.self_check_project(project["id"])
        self.assertTrue(any(issue["code"] == "history_assigned_secret" for issue in result["credential_findings"]))
        self.assertNotIn(secret, json.dumps(result, ensure_ascii=False))

    def test_self_check_isolated_project_excludes_parent_content(self) -> None:
        parent = self.root / "parent"
        child = parent / "child"
        child.mkdir(parents=True)
        subprocess.run([core._git_executable(), "-C", str(parent), "init", "-b", "main"], check=True, capture_output=True)
        (parent / "private.txt").write_text("OPENAI_" + "API_KEY=" + "sampleParentValue" * 3, encoding="utf-8")
        (child / ".gitignore").write_text("\n", encoding="utf-8")
        (child / "README.md").write_text("child only\n", encoding="utf-8")
        project = core.register_project(str(child))["project"]
        result = core.self_check_project(project["id"])
        self.assertTrue(result["project"]["isolated_subdirectory"])
        self.assertEqual(result["credential_issue_count"], 0)
        self.assertEqual(result["files"]["count"], 2)

    def test_project_execution_lock_rejects_concurrent_upload(self) -> None:
        with core._project_execution_lock("project-id"):
            with self.assertRaisesRegex(core.UploadError, "已有上传正在执行"):
                with core._project_execution_lock("project-id"):
                    self.fail("concurrent lock unexpectedly acquired")

    def test_rejects_home_and_invalid_repo_name(self) -> None:
        with self.assertRaises(core.UploadError):
            core._validate_project_path(str(Path.home()))
        project = self.register()
        (self.project / "README.md").write_text("safe\n", encoding="utf-8")
        with mock.patch.object(core, "github_owner", return_value="ExampleUser"):
            with self.assertRaises(core.UploadError):
                core.preflight_upload(project["id"], "bad;name")

    def test_rejects_relative_project_path(self) -> None:
        with mock.patch("pathlib.Path.cwd", return_value=self.root):
            with self.assertRaisesRegex(core.UploadError, "绝对路径"):
                core._validate_project_path("project")

    def test_rejects_codex_home_descendants(self) -> None:
        fake_codex_home = self.root / "codex-home"
        sensitive_child = fake_codex_home / "memories"
        sensitive_child.mkdir(parents=True)
        with mock.patch.object(core, "CODEX_HOME", fake_codex_home):
            with self.assertRaisesRegex(core.UploadError, "凭据或系统数据"):
                core._validate_project_path(str(sensitive_child))

    def test_git_symlink_and_malformed_gitfile_are_rejected(self) -> None:
        outside = self.root / "outside-git"
        outside.mkdir()
        marker = self.project / ".git"
        marker.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(core.UploadError, "符号链接"):
            core.register_project(str(self.project))
        marker.unlink()
        marker.write_text("not a gitdir\n", encoding="utf-8")
        with self.assertRaisesRegex(core.UploadError, "格式异常"):
            core.register_project(str(self.project))

    def test_sensitive_current_file_blocks_upload(self) -> None:
        project = self.register()
        (self.project / ".env").write_text(synthetic_secret_assignment(), encoding="utf-8")
        result = self.preflight(project["id"])
        self.assertFalse(result["ready"])
        codes = {issue["code"] for issue in result["issues"]}
        self.assertIn("environment_file", codes)
        serialized = json.dumps(result)
        self.assertNotIn("example_secret_value", serialized)

    def test_git_credentials_file_is_blocked(self) -> None:
        project = self.register()
        credential_value = "OrdinaryPassword12345"
        (self.project / ".git-credentials").write_text(
            synthetic_credential_url(credential_value),
            encoding="utf-8",
        )
        result = self.preflight(project["id"])
        self.assertFalse(result["ready"])
        self.assertIn("credential_file", {issue["code"] for issue in result["issues"]})
        self.assertNotIn(credential_value, json.dumps(result))

    def test_binary_current_file_secret_is_detected(self) -> None:
        project = self.register()
        secret = synthetic_github_token().encode()
        (self.project / "payload.bin").write_bytes(b"\x00" * 16 + secret)
        result = self.preflight(project["id"])
        self.assertFalse(result["ready"])
        self.assertIn("current_github_token", {issue["code"] for issue in result["issues"]})
        self.assertNotIn(secret.decode(), json.dumps(result))

    def test_secret_in_current_filename_is_detected_and_redacted(self) -> None:
        project = self.register()
        secret = synthetic_github_token()
        (self.project / f"note-{secret}.txt").write_text("safe\n", encoding="utf-8")
        result = self.preflight(project["id"])
        self.assertFalse(result["ready"])
        self.assertIn("current_path_github_token", {issue["code"] for issue in result["issues"]})
        self.assertNotIn(secret, json.dumps(result))

    def test_gitignore_excludes_sensitive_untracked_file(self) -> None:
        project = self.register()
        (self.project / ".gitignore").write_text(".env\n", encoding="utf-8")
        (self.project / ".env").write_text(synthetic_secret_assignment(), encoding="utf-8")
        (self.project / "README.md").write_text("safe\n", encoding="utf-8")
        result = self.preflight(project["id"])
        self.assertTrue(result["ready"])
        self.assertEqual(result["repository"]["visibility"], "private")

    def test_nested_gitignore_matches_future_git_add(self) -> None:
        nested = self.project / "nested"
        nested.mkdir()
        (nested / ".gitignore").write_text(".env\n", encoding="utf-8")
        (nested / ".env").write_text(synthetic_secret_assignment(), encoding="utf-8")
        (nested / "keep.txt").write_text("safe\n", encoding="utf-8")
        project = self.register()
        result = self.preflight(project["id"])
        self.assertTrue(result["ready"])
        self.assertEqual(result["files"]["count"], 2)

    def test_existing_other_origin_blocks_upload(self) -> None:
        subprocess.run([core._git_executable(), "-C", str(self.project), "init", "-b", "main"], check=True, capture_output=True)
        subprocess.run(
            [core._git_executable(), "-C", str(self.project), "remote", "add", "origin", "git@github.com:Other/elsewhere.git"],
            check=True,
            capture_output=True,
        )
        project = self.register()
        (self.project / "README.md").write_text("safe\n", encoding="utf-8")
        result = self.preflight(project["id"])
        self.assertFalse(result["ready"])
        self.assertIn("origin_conflict", {issue["code"] for issue in result["issues"]})

    def test_existing_public_target_cannot_be_presented_as_private(self) -> None:
        subprocess.run([core._git_executable(), "-C", str(self.project), "init", "-b", "main"], check=True, capture_output=True)
        subprocess.run(
            [core._git_executable(), "-C", str(self.project), "remote", "add", "origin", "git@github.com:ExampleUser/safe-project.git"],
            check=True,
            capture_output=True,
        )
        (self.project / "README.md").write_text("safe\n", encoding="utf-8")
        project = self.register()
        target = {
            "nameWithOwner": "ExampleUser/safe-project",
            "visibility": "PUBLIC",
            "url": "https://github.com/ExampleUser/safe-project",
        }
        with mock.patch.object(core, "github_owner", return_value="ExampleUser"), mock.patch.object(
            core, "_repo_view", return_value=target
        ):
            result = core.preflight_upload(project["id"], "safe-project", "private")
        self.assertFalse(result["ready"])
        self.assertIn("visibility_mismatch", {issue["code"] for issue in result["issues"]})
        self.assertEqual(result["repository"]["actual_visibility"], "public")

    def test_tracked_deletion_does_not_look_unreadable(self) -> None:
        subprocess.run([core._git_executable(), "-C", str(self.project), "init", "-b", "main"], check=True, capture_output=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.name", "Test"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.email", "test@example.invalid"], check=True)
        deleted = self.project / "old.txt"
        deleted.write_text("old\n", encoding="utf-8")
        subprocess.run([core._git_executable(), "-C", str(self.project), "add", "old.txt"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "commit", "-m", "add"], check=True, capture_output=True)
        deleted.unlink()
        (self.project / "README.md").write_text("safe\n", encoding="utf-8")
        project = self.register()
        result = self.preflight(project["id"])
        self.assertFalse(result["ready"])
        self.assertNotIn("unreadable_file", {issue["code"] for issue in result["issues"]})
        self.assertIn("dirty_repository", {issue["code"] for issue in result["issues"]})

    def test_dirty_existing_repository_is_blocked(self) -> None:
        subprocess.run([core._git_executable(), "-C", str(self.project), "init", "-b", "main"], check=True, capture_output=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.name", "Test"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.email", "test@example.invalid"], check=True)
        readme = self.project / "README.md"
        readme.write_text("first\n", encoding="utf-8")
        subprocess.run([core._git_executable(), "-C", str(self.project), "add", "README.md"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "commit", "-m", "first"], check=True, capture_output=True)
        readme.write_text("changed\n", encoding="utf-8")
        project = self.register()
        result = self.preflight(project["id"])
        self.assertFalse(result["ready"])
        self.assertIn("dirty_repository", {issue["code"] for issue in result["issues"]})

    def test_assume_unchanged_cannot_hide_worktree_change(self) -> None:
        subprocess.run([core._git_executable(), "-C", str(self.project), "init", "-b", "main"], check=True, capture_output=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.name", "Test"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.email", "test@example.invalid"], check=True)
        tracked = self.project / "a.txt"
        tracked.write_text("old\n", encoding="utf-8")
        subprocess.run([core._git_executable(), "-C", str(self.project), "add", "a.txt"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "commit", "-m", "old"], check=True, capture_output=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "update-index", "--assume-unchanged", "a.txt"], check=True)
        tracked.write_text("new\n", encoding="utf-8")
        project = self.register()
        result = self.preflight(project["id"])
        self.assertFalse(result["ready"])
        self.assertIn("hidden_index_state", {issue["code"] for issue in result["issues"]})

    def test_skip_worktree_is_blocked(self) -> None:
        subprocess.run([core._git_executable(), "-C", str(self.project), "init", "-b", "main"], check=True, capture_output=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.name", "Test"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.email", "test@example.invalid"], check=True)
        tracked = self.project / "a.txt"
        tracked.write_text("old\n", encoding="utf-8")
        subprocess.run([core._git_executable(), "-C", str(self.project), "add", "a.txt"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "commit", "-m", "old"], check=True, capture_output=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "update-index", "--skip-worktree", "a.txt"], check=True)
        project = self.register()
        result = self.preflight(project["id"])
        self.assertFalse(result["ready"])
        self.assertIn("hidden_index_state", {issue["code"] for issue in result["issues"]})

    def test_mismatched_pushurl_blocks_upload(self) -> None:
        subprocess.run([core._git_executable(), "-C", str(self.project), "init", "-b", "main"], check=True, capture_output=True)
        subprocess.run(
            [core._git_executable(), "-C", str(self.project), "remote", "add", "origin", "git@github.com:ExampleUser/safe-project.git"],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [core._git_executable(), "-C", str(self.project), "config", "remote.origin.pushurl", "git@github.com:Other/elsewhere.git"],
            check=True,
            capture_output=True,
        )
        (self.project / "README.md").write_text("safe\n", encoding="utf-8")
        project = self.register()
        result = self.preflight(project["id"])
        self.assertFalse(result["ready"])
        self.assertIn("push_url_conflict", {issue["code"] for issue in result["issues"]})

    def test_nested_repository_blocks_new_project(self) -> None:
        nested = self.project / "nested"
        nested.mkdir()
        subprocess.run([core._git_executable(), "-C", str(nested), "init", "-b", "main"], check=True, capture_output=True)
        (nested / "README.md").write_text("nested\n", encoding="utf-8")
        (self.project / "README.md").write_text("root\n", encoding="utf-8")
        project = self.register()
        result = self.preflight(project["id"])
        self.assertFalse(result["ready"])
        self.assertIn("nested_repository", {issue["code"] for issue in result["issues"]})

    def test_parent_repository_child_registers_as_isolated_snapshot(self) -> None:
        parent = self.root / "parent"
        child = parent / "child"
        child.mkdir(parents=True)
        subprocess.run([core._git_executable(), "-C", str(parent), "init", "-b", "main"], check=True, capture_output=True)
        subprocess.run([core._git_executable(), "-C", str(parent), "config", "user.name", "Test"], check=True)
        subprocess.run([core._git_executable(), "-C", str(parent), "config", "user.email", "test@example.invalid"], check=True)
        (parent / ".gitignore").write_text("child/parent-ignored.txt\n", encoding="utf-8")
        (parent / "historical-secret.txt").write_text(synthetic_github_token() + "\n", encoding="utf-8")
        subprocess.run([core._git_executable(), "-C", str(parent), "add", ".gitignore", "historical-secret.txt"], check=True)
        subprocess.run([core._git_executable(), "-C", str(parent), "commit", "-m", "parent only"], check=True, capture_output=True)

        (child / ".gitignore").write_text(".env\n", encoding="utf-8")
        (child / ".env").write_text(synthetic_secret_assignment(), encoding="utf-8")
        (child / "README.md").write_text("child project\n", encoding="utf-8")
        (child / "parent-ignored.txt").write_text("must be included\n", encoding="utf-8")
        registered = core.register_project(str(child))["project"]
        self.assertEqual(registered["upload_mode"], core.UPLOAD_MODE_ISOLATED_SUBDIRECTORY)
        self.assertTrue(registered["inside_larger_repository"])
        self.assertTrue(registered["isolated_subdirectory"])
        self.assertFalse(registered["is_git_repository"])
        self.assertEqual(registered["branch"], "main")

        result = self.preflight(registered["id"])
        self.assertTrue(result["ready"])
        self.assertEqual(result["project"]["upload_mode"], core.UPLOAD_MODE_ISOLATED_SUBDIRECTORY)
        self.assertEqual(result["files"]["count"], 3)
        self.assertEqual(result["files"]["history_blob_count"], 0)
        self.assertNotIn("current_github_token", {issue["code"] for issue in result["issues"]})

    def test_selected_nested_repository_root_keeps_its_own_git_mode(self) -> None:
        parent = self.root / "parent"
        child = parent / "child"
        child.mkdir(parents=True)
        subprocess.run([core._git_executable(), "-C", str(parent), "init", "-b", "main"], check=True, capture_output=True)
        subprocess.run([core._git_executable(), "-C", str(child), "init", "-b", "main"], check=True, capture_output=True)
        (child / "README.md").write_text("nested repository root\n", encoding="utf-8")
        project = core.register_project(str(child))["project"]
        self.assertEqual(project["upload_mode"], core.UPLOAD_MODE_STANDARD)
        self.assertTrue(project["is_git_repository"])
        self.assertFalse(project["inside_larger_repository"])
        plan = self.preflight(project["id"])
        self.assertTrue(plan["ready"])
        self.assertEqual(plan["project"]["upload_mode"], core.UPLOAD_MODE_STANDARD)

    def test_project_must_be_reregistered_when_it_moves_under_parent_git(self) -> None:
        outer = self.root / "outer"
        child = outer / "child"
        child.mkdir(parents=True)
        (child / "README.md").write_text("safe\n", encoding="utf-8")
        project = core.register_project(str(child))["project"]
        self.assertEqual(project["upload_mode"], core.UPLOAD_MODE_STANDARD)
        subprocess.run([core._git_executable(), "-C", str(outer), "init", "-b", "main"], check=True, capture_output=True)
        with self.assertRaisesRegex(core.UploadError, "重新添加"):
            self.preflight(project["id"])
        updated = core.register_project(str(child))["project"]
        self.assertEqual(updated["upload_mode"], core.UPLOAD_MODE_ISOLATED_SUBDIRECTORY)

    def test_isolated_snapshot_blocks_attribute_content_transformation(self) -> None:
        parent = self.root / "parent"
        child = parent / "child"
        child.mkdir(parents=True)
        subprocess.run([core._git_executable(), "-C", str(parent), "init", "-b", "main"], check=True, capture_output=True)
        (child / ".gitattributes").write_text("*.txt text\n", encoding="utf-8")
        (child / "notes.txt").write_bytes(b"line one\r\nline two\r\n")
        project = core.register_project(str(child))["project"]
        result = self.preflight(project["id"])
        self.assertFalse(result["ready"])
        self.assertIn("isolated_tree_unverifiable", {issue["code"] for issue in result["issues"]})

    def test_isolated_snapshot_does_not_execute_parent_git_filters(self) -> None:
        parent = self.root / "parent"
        child = parent / "child"
        child.mkdir(parents=True)
        marker = self.root / "parent-filter-executed"
        subprocess.run([core._git_executable(), "-C", str(parent), "init", "-b", "main"], check=True, capture_output=True)
        subprocess.run(
            [core._git_executable(), "-C", str(parent), "config", "filter.evil.clean", f"/usr/bin/touch {marker}; /bin/cat"],
            check=True,
        )
        (parent / ".gitattributes").write_text("child/*.txt filter=evil\n", encoding="utf-8")
        (child / ".gitignore").write_text("\n", encoding="utf-8")
        (child / "README.txt").write_text("safe\n", encoding="utf-8")
        project = core.register_project(str(child))["project"]
        result = self.preflight(project["id"])
        self.assertTrue(result["ready"])
        self.assertFalse(marker.exists())

    def test_isolated_snapshot_rejects_unbound_existing_target_and_remote_drift(self) -> None:
        parent = self.root / "parent"
        child = parent / "child"
        child.mkdir(parents=True)
        subprocess.run([core._git_executable(), "-C", str(parent), "init", "-b", "main"], check=True, capture_output=True)
        (child / ".gitignore").write_text("\n", encoding="utf-8")
        (child / "README.md").write_text("safe\n", encoding="utf-8")
        project = core.register_project(str(child))["project"]
        target = {
            "nameWithOwner": "ExampleUser/safe-project",
            "visibility": "private",
            "url": "https://github.com/ExampleUser/safe-project",
            "id": 12345,
        }
        with mock.patch.object(core, "github_owner", return_value="ExampleUser"), mock.patch.object(
            core, "_repo_view", return_value=target
        ):
            unbound = core.preflight_upload(project["id"], "safe-project")
        self.assertFalse(unbound["ready"])
        self.assertIn("target_exists", {issue["code"] for issue in unbound["issues"]})

        core._write_isolated_binding(
            project["id"],
            target="ExampleUser/safe-project",
            visibility="private",
            repository_id=12345,
            last_commit_oid="a" * 40,
            pending_commit_oid=None,
            expected_binding_fingerprint=core._isolated_binding_fingerprint(None),
        )
        with mock.patch.object(core, "github_owner", return_value="ExampleUser"), mock.patch.object(
            core, "_repo_view", return_value=target
        ), mock.patch.object(core, "_isolated_remote_branch_oid", return_value="b" * 40):
            drifted = core.preflight_upload(project["id"], "safe-project")
        self.assertFalse(drifted["ready"])
        self.assertIn("remote_branch_changed", {issue["code"] for issue in drifted["issues"]})
        entry = next(candidate for candidate in core._load_registry()["projects"] if candidate["id"] == project["id"])
        expected_binding = core._isolated_binding_fingerprint(core._isolated_remote_binding(entry))
        core._write_isolated_binding(
            project["id"],
            target="ExampleUser/safe-project",
            visibility="private",
            repository_id=12345,
            last_commit_oid="a" * 40,
            pending_commit_oid="b" * 40,
            expected_binding_fingerprint=expected_binding,
        )
        with mock.patch.object(core, "github_owner", return_value="ExampleUser"), mock.patch.object(
            core, "_repo_view", return_value=target
        ), mock.patch.object(core, "_isolated_remote_branch_oid", return_value="a" * 40):
            retry_after_failed_push = core.preflight_upload(project["id"], "safe-project")
        self.assertTrue(retry_after_failed_push["ready"])
        self.assertEqual(retry_after_failed_push["git"]["remote_base_oid"], "a" * 40)
        with mock.patch.object(core, "github_owner", return_value="ExampleUser"), mock.patch.object(
            core, "_repo_view", return_value=target
        ), mock.patch.object(core, "_isolated_remote_branch_oid", return_value="b" * 40):
            recover_after_landed_push = core.preflight_upload(project["id"], "safe-project")
        self.assertTrue(recover_after_landed_push["ready"])
        self.assertEqual(recover_after_landed_push["git"]["remote_base_oid"], "b" * 40)
        replaced_target = {**target, "id": 54321}
        with mock.patch.object(core, "github_owner", return_value="ExampleUser"), mock.patch.object(
            core, "_repo_view", return_value=replaced_target
        ):
            replaced = core.preflight_upload(project["id"], "safe-project")
        self.assertFalse(replaced["ready"])
        self.assertIn("repository_identity_changed", {issue["code"] for issue in replaced["issues"]})

    def test_isolated_snapshot_upload_and_repeat_update_leave_parent_untouched(self) -> None:
        parent = self.root / "parent"
        child = parent / "child"
        child.mkdir(parents=True)
        subprocess.run([core._git_executable(), "-C", str(parent), "init", "-b", "main"], check=True, capture_output=True)
        subprocess.run([core._git_executable(), "-C", str(parent), "config", "user.name", "Parent"], check=True)
        subprocess.run([core._git_executable(), "-C", str(parent), "config", "user.email", "parent@example.invalid"], check=True)
        (parent / "parent.txt").write_text("outside selected directory\n", encoding="utf-8")
        subprocess.run([core._git_executable(), "-C", str(parent), "add", "parent.txt"], check=True)
        subprocess.run([core._git_executable(), "-C", str(parent), "commit", "-m", "parent"], check=True, capture_output=True)
        (child / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
        (child / "ignored.txt").write_text("not uploaded\n", encoding="utf-8")
        (child / "README.md").write_text("version one\n", encoding="utf-8")
        (child / "remove-me.txt").write_text("remove later\n", encoding="utf-8")
        project = core.register_project(str(child))["project"]
        parent_head_before = subprocess.run(
            [core._git_executable(), "-C", str(parent), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        parent_status_before = subprocess.run(
            [core._git_executable(), "-C", str(parent), "status", "--porcelain=v1", "--untracked-files=all"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        parent_config_before = (parent / ".git" / "config").read_bytes()
        parent_index_before = (parent / ".git" / "index").read_bytes()

        remote = self.root / "remote.git"
        subprocess.run([core._git_executable(), "init", "--bare", str(remote)], check=True, capture_output=True)
        target = {
            "nameWithOwner": "ExampleUser/safe-project",
            "visibility": "private",
            "url": "https://github.com/ExampleUser/safe-project",
            "id": 12345,
        }
        original_run = core.run_command

        def localize_network(args: list[str], **kwargs: object) -> core.CommandResult:
            if any(isinstance(value, str) and value == "git@github.com:ExampleUser/safe-project.git" for value in args):
                localized = [str(remote) if value == "git@github.com:ExampleUser/safe-project.git" else value for value in args]
                localized = ["protocol.file.allow=always" if value == "protocol.file.allow=never" else value for value in localized]
                return original_run(localized, **kwargs)
            return original_run(args, **kwargs)

        with mock.patch.object(core, "github_owner", return_value="ExampleUser"), mock.patch.object(
            core, "_repo_view", return_value=None
        ):
            first_plan = core.preflight_upload(project["id"], "safe-project")
        self.assertTrue(first_plan["ready"])
        with mock.patch.object(core, "github_owner", return_value="ExampleUser"), mock.patch.object(
            core, "_repo_view", side_effect=[None, target, target, target]
        ), mock.patch.object(
            core, "_create_repository", return_value=target
        ), mock.patch.object(core, "_gh_executable", return_value="/usr/bin/true"), mock.patch.object(
            core, "run_command", side_effect=localize_network
        ):
            first = core.execute_upload(first_plan["plan_id"])
        self.assertTrue(first["uploaded"])
        self.assertTrue(first["created_repository"])
        self.assertTrue(first["created_commit"])
        first_oid = first["commit_oid"]
        self.assertEqual(
            subprocess.run(
                [core._git_executable(), f"--git-dir={remote}", "rev-list", "--parents", "-n", "1", first_oid],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip().split(),
            [first_oid],
        )
        self.assertEqual(
            subprocess.run(
                [core._git_executable(), f"--git-dir={remote}", "ls-tree", "-r", "--name-only", first_oid],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.splitlines(),
            [".gitignore", "README.md", "remove-me.txt"],
        )
        self.assertFalse((child / ".git").exists())
        self.assertEqual((parent / ".git" / "config").read_bytes(), parent_config_before)
        self.assertEqual((parent / ".git" / "index").read_bytes(), parent_index_before)
        self.assertEqual(
            subprocess.run(
                [core._git_executable(), "-C", str(parent), "status", "--porcelain=v1", "--untracked-files=all"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout,
            parent_status_before,
        )

        (child / "README.md").write_text("version two\n", encoding="utf-8")
        (child / "remove-me.txt").unlink()
        executable = child / "run.sh"
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o755)
        second_parent_status_before = subprocess.run(
            [core._git_executable(), "-C", str(parent), "status", "--porcelain=v1", "--untracked-files=all"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        second_parent_index_before = (parent / ".git" / "index").read_bytes()
        with mock.patch.object(core, "github_owner", return_value="ExampleUser"), mock.patch.object(
            core, "_repo_view", return_value=target
        ), mock.patch.object(core, "run_command", side_effect=localize_network):
            second_plan = core.preflight_upload(project["id"], "safe-project")
        self.assertTrue(second_plan["ready"])
        self.assertEqual(second_plan["git"]["remote_base_oid"], first_oid)
        with mock.patch.object(core, "github_owner", return_value="ExampleUser"), mock.patch.object(
            core, "_repo_view", return_value=target
        ), mock.patch.object(core, "_gh_executable", return_value="/usr/bin/true"), mock.patch.object(
            core, "run_command", side_effect=localize_network
        ):
            second = core.execute_upload(second_plan["plan_id"])
        self.assertTrue(second["uploaded"])
        self.assertTrue(second["created_commit"])
        second_oid = second["commit_oid"]
        remote_parents = subprocess.run(
            [core._git_executable(), f"--git-dir={remote}", "rev-list", "--parents", "-n", "1", second_oid],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip().split()
        self.assertEqual(remote_parents, [second_oid, first_oid])
        remote_tree = subprocess.run(
            [core._git_executable(), f"--git-dir={remote}", "ls-tree", "-r", "--name-only", second_oid],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.splitlines()
        self.assertEqual(remote_tree, [".gitignore", "README.md", "run.sh"])
        remote_mode = subprocess.run(
            [core._git_executable(), f"--git-dir={remote}", "ls-tree", second_oid, "run.sh"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.split()[0]
        self.assertEqual(remote_mode, "100755")

        self.assertFalse((child / ".git").exists())
        self.assertEqual((parent / ".git" / "config").read_bytes(), parent_config_before)
        self.assertEqual((parent / ".git" / "index").read_bytes(), second_parent_index_before)
        self.assertEqual(
            subprocess.run(
                [core._git_executable(), "-C", str(parent), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout,
            parent_head_before,
        )
        self.assertEqual(
            subprocess.run(
                [core._git_executable(), "-C", str(parent), "status", "--porcelain=v1", "--untracked-files=all"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout,
            second_parent_status_before,
        )

        with mock.patch.object(core, "github_owner", return_value="ExampleUser"), mock.patch.object(
            core, "_repo_view", return_value=target
        ), mock.patch.object(core, "run_command", side_effect=localize_network):
            unchanged_plan = core.preflight_upload(project["id"], "safe-project")
        with mock.patch.object(core, "github_owner", return_value="ExampleUser"), mock.patch.object(
            core, "_repo_view", return_value=target
        ), mock.patch.object(core, "_gh_executable", return_value="/usr/bin/true"), mock.patch.object(
            core, "run_command", side_effect=localize_network
        ):
            unchanged = core.execute_upload(unchanged_plan["plan_id"])
        self.assertFalse(unchanged["created_commit"])
        self.assertEqual(unchanged["commit_oid"], second_oid)

        for candidate in child.iterdir():
            candidate.unlink()
        empty_parent_status_before = subprocess.run(
            [core._git_executable(), "-C", str(parent), "status", "--porcelain=v1", "--untracked-files=all"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        empty_parent_index_before = (parent / ".git" / "index").read_bytes()
        with mock.patch.object(core, "github_owner", return_value="ExampleUser"), mock.patch.object(
            core, "_repo_view", return_value=target
        ), mock.patch.object(core, "run_command", side_effect=localize_network):
            empty_plan = core.preflight_upload(project["id"], "safe-project")
        self.assertTrue(empty_plan["ready"])
        with mock.patch.object(core, "github_owner", return_value="ExampleUser"), mock.patch.object(
            core, "_repo_view", return_value=target
        ), mock.patch.object(core, "_gh_executable", return_value="/usr/bin/true"), mock.patch.object(
            core, "run_command", side_effect=localize_network
        ):
            emptied = core.execute_upload(empty_plan["plan_id"])
        self.assertTrue(emptied["created_commit"])
        self.assertEqual(
            subprocess.run(
                [core._git_executable(), f"--git-dir={remote}", "rev-list", "--parents", "-n", "1", emptied["commit_oid"]],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip().split(),
            [emptied["commit_oid"], second_oid],
        )
        self.assertEqual(
            subprocess.run(
                [core._git_executable(), f"--git-dir={remote}", "ls-tree", "-r", "--name-only", emptied["commit_oid"]],
                check=True,
                capture_output=True,
                text=True,
            ).stdout,
            "",
        )
        self.assertFalse((child / ".git").exists())
        self.assertEqual((parent / ".git" / "index").read_bytes(), empty_parent_index_before)
        self.assertEqual(
            subprocess.run(
                [core._git_executable(), "-C", str(parent), "status", "--porcelain=v1", "--untracked-files=all"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout,
            empty_parent_status_before,
        )

        (child / "replacement-race.txt").write_text("detect replacement\n", encoding="utf-8")
        with mock.patch.object(core, "github_owner", return_value="ExampleUser"), mock.patch.object(
            core, "_repo_view", return_value=target
        ), mock.patch.object(core, "run_command", side_effect=localize_network):
            replacement_plan = core.preflight_upload(project["id"], "safe-project")
        replacement_target = {**target, "id": 54321}
        with mock.patch.object(core, "github_owner", return_value="ExampleUser"), mock.patch.object(
            core, "_repo_view", side_effect=[target, target, target, replacement_target]
        ), mock.patch.object(core, "_gh_executable", return_value="/usr/bin/true"), mock.patch.object(
            core, "run_command", side_effect=localize_network
        ):
            with self.assertRaisesRegex(core.UploadError, "推送后无法确认"):
                core.execute_upload(replacement_plan["plan_id"])
        replacement_oid = subprocess.run(
            [core._git_executable(), f"--git-dir={remote}", "rev-parse", "refs/heads/main"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        self.assertNotEqual(replacement_oid, emptied["commit_oid"])
        entry = next(candidate for candidate in core._load_registry()["projects"] if candidate["id"] == project["id"])
        binding = core._isolated_remote_binding(entry)
        self.assertEqual(binding["repository_id"], target["id"])
        self.assertEqual(binding["last_commit_oid"], emptied["commit_oid"])
        self.assertEqual(binding["pending_commit_oid"], replacement_oid)

    def test_http_remote_is_sanitized(self) -> None:
        remote = "https:" + "//secret-user:secret-pass@github.com/ExampleUser/safe-project.git?access_token=topsecret#fragment"
        sanitized = core._safe_remote_url(remote)
        self.assertEqual(sanitized, "https://github.com/ExampleUser/safe-project.git")
        self.assertNotIn("secret", sanitized)
        self.assertNotIn("access_token", sanitized)
        self.assertEqual(core._github_slug_from_remote(remote), "exampleuser/safe-project")
        scp_user = "gh" + "p_example_secret"
        scp_remote = scp_user + "@github.com:ExampleUser/safe-project.git"
        sanitized_scp = core._safe_remote_url(scp_remote)
        self.assertEqual(sanitized_scp, "***@github.com:ExampleUser/safe-project.git")
        self.assertNotIn(scp_user, sanitized_scp)
        self.assertEqual(core._github_slug_from_remote(scp_remote), "exampleuser/safe-project")

        ssh_remote = "ssh://git@github.com/ExampleUser/safe-project.git?access_token=TOPSECRETVALUE#fragment"
        sanitized_ssh = core._safe_remote_url(ssh_remote)
        self.assertEqual(sanitized_ssh, "ssh://github.com/ExampleUser/safe-project.git")
        self.assertNotIn("TOPSECRETVALUE", sanitized_ssh)
        scp_query = "git@github.com:ExampleUser/safe-project.git?access_token=TOPSECRETVALUE#fragment"
        self.assertEqual(core._safe_remote_url(scp_query), "***@github.com:ExampleUser/safe-project.git")
        malformed_scheme = synthetic_credential_url("SuperSecretPassword", "github.com:bad/owner/repo.git")
        malformed_scp = "user:SuperSecretPassword@github.com:owner/repo.git"
        self.assertEqual(core._safe_remote_url(malformed_scheme), "[REDACTED_REMOTE]")
        self.assertEqual(core._safe_remote_url(malformed_scp), "***@github.com:owner/repo.git")
        self.assertNotIn("SuperSecretPassword", core._safe_remote_url(malformed_scheme))
        self.assertNotIn("SuperSecretPassword", core._safe_remote_url(malformed_scp))

    def test_repo_view_only_treats_explicit_404_as_missing(self) -> None:
        with mock.patch.object(core, "_gh_executable", return_value="gh"), mock.patch.object(
            core, "run_command", return_value=core.CommandResult(1, "", "gh: Not Found (HTTP 404)")
        ):
            self.assertIsNone(core._repo_view("ExampleUser", "missing"))
        with mock.patch.object(core, "_gh_executable", return_value="gh"), mock.patch.object(
            core, "run_command", return_value=core.CommandResult(1, "", "network unavailable")
        ):
            with self.assertRaisesRegex(core.UploadError, "无法确认"):
                core._repo_view("ExampleUser", "missing")
        with mock.patch.object(core, "_gh_executable", return_value="gh"), mock.patch.object(
            core, "run_command", return_value=core.CommandResult(0, "not-json", "")
        ):
            with self.assertRaisesRegex(core.UploadError, "无法解析"):
                core._repo_view("ExampleUser", "missing")

    def test_create_repository_captures_identity_from_creation_response(self) -> None:
        response = {
            "full_name": "ExampleUser/safe-project",
            "html_url": "https://github.com/ExampleUser/safe-project",
            "visibility": "private",
            "private": True,
            "id": 12345,
        }
        with mock.patch.object(core, "_gh_executable", return_value="gh"), mock.patch.object(
            core,
            "run_command",
            return_value=core.CommandResult(0, json.dumps(response), ""),
        ) as command:
            created = core._create_repository("ExampleUser", "safe-project", "private")
        self.assertEqual(created["id"], 12345)
        self.assertEqual(
            command.call_args.args[0],
            ["gh", "api", "--method", "POST", "user/repos", "--input", "-"],
        )
        self.assertEqual(
            json.loads(command.call_args.kwargs["input_text"]),
            {"name": "safe-project", "private": True},
        )

    def test_isolated_creation_never_binds_a_same_name_replacement(self) -> None:
        parent = self.root / "parent"
        child = parent / "child"
        child.mkdir(parents=True)
        subprocess.run([core._git_executable(), "-C", str(parent), "init", "-b", "main"], check=True, capture_output=True)
        (child / "README.md").write_text("safe\n", encoding="utf-8")
        project = core.register_project(str(child))["project"]
        with mock.patch.object(core, "github_owner", return_value="ExampleUser"), mock.patch.object(
            core, "_repo_view", return_value=None
        ):
            plan = core.preflight_upload(project["id"], "safe-project")
        created_target = {
            "nameWithOwner": "ExampleUser/safe-project",
            "visibility": "private",
            "url": "https://github.com/ExampleUser/safe-project",
            "id": 12345,
        }
        replacement_target = {**created_target, "id": 54321}
        original_run = core.run_command
        pushes: list[list[str]] = []

        def capture_push(args: list[str], **kwargs: object) -> core.CommandResult:
            if "push" in args:
                pushes.append(args)
            return original_run(args, **kwargs)

        with mock.patch.object(core, "github_owner", return_value="ExampleUser"), mock.patch.object(
            core, "_repo_view", side_effect=[None, replacement_target]
        ), mock.patch.object(core, "_create_repository", return_value=created_target), mock.patch.object(
            core, "run_command", side_effect=capture_push
        ):
            with self.assertRaisesRegex(core.UploadError, "固定身份已变化"):
                core.execute_upload(plan["plan_id"])
        self.assertEqual(pushes, [])
        entry = next(candidate for candidate in core._load_registry()["projects"] if candidate["id"] == project["id"])
        binding = core._isolated_remote_binding(entry)
        self.assertIsNone(binding["repository_id"])
        self.assertIsNone(binding["last_commit_oid"])
        self.assertIsNotNone(binding["pending_commit_oid"])

    def test_git_commands_disable_project_execution_paths(self) -> None:
        command = core._git_command(self.project, "status")
        joined = " ".join(command)
        self.assertEqual(command[1], "--no-replace-objects")
        self.assertEqual(command[2], "--no-lazy-fetch")
        self.assertIn("core.hooksPath=/dev/null", joined)
        self.assertIn("core.fsmonitor=false", joined)
        self.assertIn("commit.gpgSign=false", joined)
        self.assertIn("core.attributesFile=/dev/null", joined)
        self.assertIn("maintenance.auto=false", joined)
        self.assertIn("gc.auto=0", joined)

    def test_run_command_removes_inherited_git_config_injection(self) -> None:
        target = "git@github.com:ExampleUser/safe-project.git"
        injected = {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "url.ssh://evil.example/.insteadOf",
            "GIT_CONFIG_VALUE_0": "git@github.com:",
        }
        with mock.patch.dict(os.environ, injected):
            result = core.run_command([core._git_executable(), "ls-remote", "--get-url", target])
        self.assertEqual(result.stdout.strip(), target)

    def test_bare_repository_is_rejected(self) -> None:
        subprocess.run([core._git_executable(), "init", "--bare", str(self.project)], check=True, capture_output=True)
        with self.assertRaisesRegex(core.UploadError, "bare Git"):
            core.register_project(str(self.project))

    def test_fixed_push_does_not_follow_annotated_tags(self) -> None:
        remote = self.root / "remote.git"
        subprocess.run([core._git_executable(), "init", "--bare", str(remote)], check=True, capture_output=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "init", "-b", "main"], check=True, capture_output=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.name", "Test"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "push.followTags", "true"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "push.recurseSubmodules", "only"], check=True)
        (self.project / "README.md").write_text("safe\n", encoding="utf-8")
        subprocess.run([core._git_executable(), "-C", str(self.project), "add", "README.md"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "commit", "-m", "safe"], check=True, capture_output=True)
        subprocess.run(
            [core._git_executable(), "-C", str(self.project), "tag", "-a", "v1", "-m", "unconfirmed tag"],
            check=True,
            capture_output=True,
        )
        oid = subprocess.run(
            [core._git_executable(), "-C", str(self.project), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        with core._isolated_push_repository(self.project, oid) as (_, git_dir, transport_env):
            command = core._git_push_command(git_dir, str(remote), oid, "main")
            self.assertIn("--no-follow-tags", command)
            self.assertIn("--no-push-option", command)
            self.assertIn("--recurse-submodules=no", command)
            self.assertIn("push.gpgSign=false", command)
            insertion = next(index for index, value in enumerate(command) if value.startswith("--git-dir="))
            command[insertion:insertion] = ["-c", "protocol.file.allow=always"]
            result = core.run_command(command, check=False, env_overrides=transport_env)
        self.assertEqual(result.returncode, 0, result.stderr)
        refs = subprocess.run(
            [core._git_executable(), "--git-dir", str(remote), "for-each-ref", "--format=%(refname)"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.splitlines()
        self.assertEqual(refs, ["refs/heads/main"])

    def test_isolated_push_ignores_url_shaped_remote_section(self) -> None:
        safe_remote = self.root / "safe.git"
        evil_remote = self.root / "evil.git"
        subprocess.run([core._git_executable(), "init", "--bare", str(safe_remote)], check=True, capture_output=True)
        subprocess.run([core._git_executable(), "init", "--bare", str(evil_remote)], check=True, capture_output=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "init", "-b", "main"], check=True, capture_output=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.name", "Test"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.email", "test@example.invalid"], check=True)
        (self.project / "README.md").write_text("safe\n", encoding="utf-8")
        subprocess.run([core._git_executable(), "-C", str(self.project), "add", "README.md"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "commit", "-m", "safe"], check=True, capture_output=True)
        oid = subprocess.run(
            [core._git_executable(), "-C", str(self.project), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        with (self.project / ".git" / "config").open("a", encoding="utf-8") as handle:
            handle.write(
                f'\n[remote "{safe_remote}"]\n\turl = {safe_remote}\n'
                f"\tpushurl = {safe_remote}\n\tpushurl = {evil_remote}\n"
            )
        with core._isolated_push_repository(self.project, oid) as (_, git_dir, transport_env):
            command = core._git_push_command(git_dir, str(safe_remote), oid, "main")
            insertion = next(index for index, value in enumerate(command) if value.startswith("--git-dir="))
            command[insertion:insertion] = ["-c", "protocol.file.allow=always"]
            result = core.run_command(command, check=False, env_overrides=transport_env)
        self.assertEqual(result.returncode, 0, result.stderr)
        safe_oid = subprocess.run(
            [core._git_executable(), "--git-dir", str(safe_remote), "rev-parse", "refs/heads/main"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        self.assertEqual(safe_oid, oid)
        evil_check = subprocess.run(
            [core._git_executable(), "--git-dir", str(evil_remote), "rev-parse", "--verify", "refs/heads/main"],
            check=False,
            capture_output=True,
        )
        self.assertNotEqual(evil_check.returncode, 0)

    def test_git_replace_refs_cannot_hide_original_secret(self) -> None:
        subprocess.run([core._git_executable(), "-C", str(self.project), "init", "-b", "main"], check=True, capture_output=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.name", "Test"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.email", "test@example.invalid"], check=True)
        secret = synthetic_github_token()
        data = self.project / "data.txt"
        data.write_text(secret + "\n", encoding="utf-8")
        subprocess.run([core._git_executable(), "-C", str(self.project), "add", "data.txt"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "commit", "-m", "secret"], check=True, capture_output=True)
        original_oid = subprocess.run(
            [core._git_executable(), "-C", str(self.project), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        data.write_text("safe\n", encoding="utf-8")
        subprocess.run([core._git_executable(), "-C", str(self.project), "add", "data.txt"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "commit", "-m", "safe"], check=True, capture_output=True)
        safe_oid = subprocess.run(
            [core._git_executable(), "-C", str(self.project), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        subprocess.run([core._git_executable(), "-C", str(self.project), "reset", "--hard", original_oid], check=True, capture_output=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "replace", original_oid, safe_oid], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "reset", "--hard", "HEAD"], check=True, capture_output=True)
        self.assertEqual(data.read_text(encoding="utf-8"), "safe\n")
        project = self.register()
        result = self.preflight(project["id"])
        codes = {issue["code"] for issue in result["issues"]}
        self.assertFalse(result["ready"])
        self.assertIn("git_replace_refs", codes)
        self.assertIn("history_github_token", codes)
        self.assertNotIn(secret, json.dumps(result))

    def test_shallow_repository_is_blocked_and_raw_parent_is_not_root(self) -> None:
        subprocess.run([core._git_executable(), "-C", str(self.project), "init", "-b", "main"], check=True, capture_output=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.name", "Test"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.email", "test@example.invalid"], check=True)
        private = self.project / "private-notes.txt"
        private.write_text("unreviewed private history\n", encoding="utf-8")
        subprocess.run([core._git_executable(), "-C", str(self.project), "add", "private-notes.txt"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "commit", "-m", "parent"], check=True, capture_output=True)
        private.unlink()
        (self.project / "README.md").write_text("safe\n", encoding="utf-8")
        subprocess.run([core._git_executable(), "-C", str(self.project), "add", "-A"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "commit", "-m", "tip"], check=True, capture_output=True)
        tip = subprocess.run(
            [core._git_executable(), "-C", str(self.project), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        (self.project / ".git" / "shallow").write_text(f"{tip}\n", encoding="ascii")
        project = self.register()
        result = self.preflight(project["id"])
        self.assertFalse(result["ready"])
        self.assertIn("shallow_repository_unsupported", {issue["code"] for issue in result["issues"]})
        self.assertFalse(core._commit_is_root(self.project, tip))
        with self.assertRaisesRegex(core.UploadError, "浅克隆"):
            with core._isolated_push_repository(self.project, tip):
                pass

    def test_safe_push_environment_ignores_global_url_rewrite(self) -> None:
        malicious_config = self.root / "malicious.gitconfig"
        malicious_config.write_text(
            '[url "ssh://evil.example/"]\n\tinsteadOf = git@github.com:\n',
            encoding="utf-8",
        )
        target = "git@github.com:ExampleUser/safe-project.git"
        with mock.patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": str(malicious_config)}):
            result = core.run_command(
                [core._git_executable(), "ls-remote", "--get-url", target],
                env_overrides=core.SAFE_PUSH_ENV,
            )
        self.assertEqual(result.stdout.strip(), target)

    def test_partial_clone_ext_remote_is_blocked_without_execution(self) -> None:
        subprocess.run([core._git_executable(), "-C", str(self.project), "init", "-b", "main"], check=True, capture_output=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.name", "Test"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.email", "test@example.invalid"], check=True)
        (self.project / "README.md").write_text("safe\n", encoding="utf-8")
        subprocess.run([core._git_executable(), "-C", str(self.project), "add", "README.md"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "commit", "-m", "safe"], check=True, capture_output=True)
        marker = self.root / "must-not-exist"
        remote = f"ext::/usr/bin/touch {marker}"
        subprocess.run([core._git_executable(), "-C", str(self.project), "remote", "add", "origin", remote], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "remote.origin.promisor", "true"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "remote.origin.partialclonefilter", "blob:none"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "protocol.ext.allow", "always"], check=True)
        project = self.register()
        result = self.preflight(project["id"])
        self.assertFalse(result["ready"])
        self.assertIn("partial_clone_unsupported", {issue["code"] for issue in result["issues"]})
        self.assertFalse(marker.exists())

    def test_missing_partial_clone_blob_never_invokes_ext_remote(self) -> None:
        source = self.root / "source"
        bare = self.root / "source.git"
        partial = self.root / "partial"
        source.mkdir()
        subprocess.run([core._git_executable(), "-C", str(source), "init", "-b", "main"], check=True, capture_output=True)
        subprocess.run([core._git_executable(), "-C", str(source), "config", "user.name", "Test"], check=True)
        subprocess.run([core._git_executable(), "-C", str(source), "config", "user.email", "test@example.invalid"], check=True)
        tracked = source / "data.txt"
        tracked.write_text("old\n", encoding="utf-8")
        subprocess.run([core._git_executable(), "-C", str(source), "add", "data.txt"], check=True)
        subprocess.run([core._git_executable(), "-C", str(source), "commit", "-m", "old"], check=True, capture_output=True)
        old_blob = subprocess.run(
            [core._git_executable(), "-C", str(source), "rev-parse", "HEAD:data.txt"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        tracked.write_text("safe\n", encoding="utf-8")
        subprocess.run([core._git_executable(), "-C", str(source), "add", "data.txt"], check=True)
        subprocess.run([core._git_executable(), "-C", str(source), "commit", "-m", "safe"], check=True, capture_output=True)
        subprocess.run([core._git_executable(), "clone", "--bare", str(source), str(bare)], check=True, capture_output=True)
        subprocess.run(
            [core._git_executable(), "--git-dir", str(bare), "config", "uploadpack.allowFilter", "true"],
            check=True,
        )
        subprocess.run(
            [core._git_executable(), "clone", "--filter=blob:none", f"file://{bare}", str(partial)],
            check=True,
            capture_output=True,
        )
        missing = subprocess.run(
            [core._git_executable(), "--no-lazy-fetch", "-C", str(partial), "cat-file", "-e", old_blob],
            env={**os.environ, "GIT_NO_LAZY_FETCH": "1"},
            check=False,
            capture_output=True,
        )
        self.assertNotEqual(missing.returncode, 0)
        marker = self.root / "lazy-fetch-executed"
        subprocess.run(
            [core._git_executable(), "-C", str(partial), "remote", "set-url", "origin", f"ext::/usr/bin/touch {marker}"],
            check=True,
        )
        subprocess.run([core._git_executable(), "-C", str(partial), "config", "protocol.ext.allow", "always"], check=True)
        snapshot = core._snapshot(partial.resolve())
        self.assertGreater(snapshot["blocking_issue_count"], 0)
        self.assertIn("partial_clone_unsupported", {issue["code"] for issue in snapshot["issues"]})
        self.assertFalse(marker.exists())

    def test_git_status_failure_blocks_snapshot(self) -> None:
        subprocess.run([core._git_executable(), "-C", str(self.project), "init", "-b", "main"], check=True, capture_output=True)
        (self.project / "README.md").write_text("safe\n", encoding="utf-8")
        original = core.run_command

        def fail_status(args: list[str], **kwargs: object) -> core.CommandResult:
            if "status" in args:
                return core.CommandResult(1, "", "simulated failure")
            return original(args, **kwargs)

        with mock.patch.object(core, "run_command", side_effect=fail_status):
            snapshot = core._snapshot(self.project.resolve())
        self.assertFalse(snapshot["is_clean"])
        self.assertIn("git_status_failed", {issue["code"] for issue in snapshot["issues"]})

    def test_local_config_include_is_blocked(self) -> None:
        subprocess.run([core._git_executable(), "-C", str(self.project), "init", "-b", "main"], check=True, capture_output=True)
        included = self.root / "included.gitconfig"
        included.write_text('[url "ssh://evil.example/"]\n\tinsteadOf = git@github.com:\n', encoding="utf-8")
        subprocess.run(
            [core._git_executable(), "-C", str(self.project), "config", "--local", "include.path", str(included)],
            check=True,
            capture_output=True,
        )
        (self.project / "README.md").write_text("safe\n", encoding="utf-8")
        project = self.register()
        result = self.preflight(project["id"])
        self.assertFalse(result["ready"])
        self.assertIn("executable_git_config", {issue["code"] for issue in result["issues"]})

    def test_worktree_config_transport_rewrite_is_blocked(self) -> None:
        subprocess.run([core._git_executable(), "-C", str(self.project), "init", "-b", "main"], check=True, capture_output=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.name", "Test"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.email", "test@example.invalid"], check=True)
        (self.project / "README.md").write_text("safe\n", encoding="utf-8")
        subprocess.run([core._git_executable(), "-C", str(self.project), "add", "README.md"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "commit", "-m", "safe"], check=True, capture_output=True)
        subprocess.run(
            [core._git_executable(), "-C", str(self.project), "config", "extensions.worktreeConfig", "true"],
            check=True,
        )
        subprocess.run(
            [
                core._git_executable(),
                "-C",
                str(self.project),
                "config",
                "--worktree",
                "url.ssh://evil.example/.insteadOf",
                "git@github.com:",
            ],
            check=True,
        )
        project = self.register()
        result = self.preflight(project["id"])
        self.assertFalse(result["ready"])
        self.assertIn("executable_git_config", {issue["code"] for issue in result["issues"]})

    def test_preflight_does_not_execute_local_clean_filter(self) -> None:
        subprocess.run([core._git_executable(), "-C", str(self.project), "init", "-b", "main"], check=True, capture_output=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.name", "Test"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.email", "test@example.invalid"], check=True)
        (self.project / ".gitattributes").write_text("*.txt filter=evil\n", encoding="utf-8")
        (self.project / "data.txt").write_text("safe\n", encoding="utf-8")
        subprocess.run([core._git_executable(), "-C", str(self.project), "add", ".gitattributes", "data.txt"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "commit", "-m", "safe"], check=True, capture_output=True)
        marker = self.root / "filter-ran"
        subprocess.run(
            [
                core._git_executable(),
                "-C",
                str(self.project),
                "config",
                "filter.evil.clean",
                f"/usr/bin/touch {marker}; /bin/cat",
            ],
            check=True,
        )
        project = self.register()
        result = self.preflight(project["id"])
        self.assertFalse(result["ready"])
        self.assertIn("external_git_filter", {issue["code"] for issue in result["issues"]})
        self.assertFalse(marker.exists())

    def test_maintenance_hook_config_is_blocked_without_execution(self) -> None:
        subprocess.run([core._git_executable(), "-C", str(self.project), "init", "-b", "main"], check=True, capture_output=True)
        marker = self.root / "maintenance-ran"
        hook = self.root / "recent-objects-hook"
        hook.write_text(f"#!/bin/sh\n/usr/bin/touch {marker}\n", encoding="utf-8")
        hook.chmod(0o755)
        subprocess.run(
            [core._git_executable(), "-C", str(self.project), "config", "gc.recentObjectsHook", str(hook)],
            check=True,
        )
        (self.project / "README.md").write_text("safe\n", encoding="utf-8")
        project = self.register()
        result = self.preflight(project["id"])
        self.assertFalse(result["ready"])
        self.assertIn("executable_git_config", {issue["code"] for issue in result["issues"]})
        self.assertFalse(marker.exists())

    def test_ignored_gitattributes_filter_is_blocked(self) -> None:
        marker = self.root / "global-filter-ran"
        global_config = self.root / "global.gitconfig"
        subprocess.run(
            [
                core._git_executable(),
                "config",
                "--file",
                str(global_config),
                "filter.evil.clean",
                f"/usr/bin/touch {marker}; /bin/cat",
            ],
            check=True,
        )
        (self.project / ".gitignore").write_text(".gitattributes\n", encoding="utf-8")
        (self.project / ".gitattributes").write_text("*.txt filter=evil\n", encoding="utf-8")
        (self.project / "data.txt").write_text("safe\n", encoding="utf-8")
        project = self.register()
        with mock.patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": str(global_config)}):
            result = self.preflight(project["id"])
        self.assertFalse(result["ready"])
        self.assertIn("external_git_filter", {issue["code"] for issue in result["issues"]})
        self.assertFalse(marker.exists())

    def test_same_size_worktree_change_cannot_hide_behind_stat_config(self) -> None:
        subprocess.run([core._git_executable(), "-C", str(self.project), "init", "-b", "main"], check=True, capture_output=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.name", "Test"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.email", "test@example.invalid"], check=True)
        tracked = self.project / "data.txt"
        tracked.write_text("AAAA\n", encoding="utf-8")
        subprocess.run([core._git_executable(), "-C", str(self.project), "add", "data.txt"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "commit", "-m", "safe"], check=True, capture_output=True)
        original = tracked.stat()
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "core.trustctime", "false"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "core.checkStat", "minimal"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "core.fileMode", "false"], check=True)
        tracked.write_text("BBBB\n", encoding="utf-8")
        os.utime(tracked, ns=(original.st_atime_ns, original.st_mtime_ns))
        project = self.register()
        result = self.preflight(project["id"])
        self.assertFalse(result["ready"])
        self.assertIn("worktree_index_mismatch", {issue["code"] for issue in result["issues"]})

    def test_clean_existing_lfs_repository_is_blocked(self) -> None:
        subprocess.run([core._git_executable(), "-C", str(self.project), "init", "-b", "main"], check=True, capture_output=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.name", "Test"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.email", "test@example.invalid"], check=True)
        (self.project / ".gitattributes").write_text("*.bin filter=lfs diff=lfs merge=lfs -text\n", encoding="utf-8")
        (self.project / "README.md").write_text("safe\n", encoding="utf-8")
        subprocess.run([core._git_executable(), "-C", str(self.project), "add", ".gitattributes", "README.md"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "commit", "-m", "add attributes"], check=True, capture_output=True)
        project = self.register()
        result = self.preflight(project["id"])
        self.assertFalse(result["ready"])
        self.assertIn("external_git_filter", {issue["code"] for issue in result["issues"]})

    def test_uppercase_gitattributes_filter_is_blocked(self) -> None:
        (self.project / ".GITATTRIBUTES").write_text("*.txt filter=evil\n", encoding="utf-8")
        (self.project / "README.txt").write_text("safe\n", encoding="utf-8")
        project = self.register()
        result = self.preflight(project["id"])
        self.assertFalse(result["ready"])
        self.assertIn("external_git_filter", {issue["code"] for issue in result["issues"]})

    def test_git_lfs_pointer_is_blocked(self) -> None:
        pointer = (
            "version https://git-lfs.github.com/spec/v1\n"
            "oid sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"
            "size 123456\n"
        )
        (self.project / "model.bin").write_text(pointer, encoding="utf-8")
        project = self.register()
        result = self.preflight(project["id"])
        self.assertFalse(result["ready"])
        self.assertIn("current_git_lfs_pointer", {issue["code"] for issue in result["issues"]})

    def test_history_inventory_failure_is_not_treated_as_safe(self) -> None:
        with mock.patch.object(
            core,
            "run_command",
            return_value=core.CommandResult(1, "", "simulated failure"),
        ):
            with self.assertRaisesRegex(core.UploadError, "Git 历史"):
                core._history_object_inventory(self.project)

    def test_execute_pushes_fixed_oid_to_fixed_github_url(self) -> None:
        subprocess.run([core._git_executable(), "-C", str(self.project), "init", "-b", "main"], check=True, capture_output=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.name", "Test"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.email", "test@example.invalid"], check=True)
        (self.project / "README.md").write_text("safe\n", encoding="utf-8")
        project = self.register()
        plan = self.preflight(project["id"])
        self.assertTrue(plan["ready"])
        target = {
            "nameWithOwner": "ExampleUser/safe-project",
            "visibility": "private",
            "url": "https://github.com/ExampleUser/safe-project",
        }
        original = core.run_command
        pushes: list[tuple[list[str], dict[str, object]]] = []

        def capture_push(args: list[str], **kwargs: object) -> core.CommandResult:
            if "push" in args:
                pushes.append((args, kwargs))
                return core.CommandResult(0, "", "")
            if "ls-remote" in args and pushes:
                oid = pushes[-1][0][-1].split(":", 1)[0]
                return core.CommandResult(0, f"{oid}\t{args[-1]}\n", "")
            return original(args, **kwargs)

        with mock.patch.object(core, "github_owner", return_value="ExampleUser"), mock.patch.object(
            core, "_repo_view", side_effect=[None, target]
        ), mock.patch.object(core, "_gh_executable", return_value="/usr/bin/true"), mock.patch.object(
            core, "run_command", side_effect=capture_push
        ):
            result = core.execute_upload(plan["plan_id"])
        self.assertTrue(result["uploaded"])
        self.assertEqual(len(pushes), 1)
        command, kwargs = pushes[0]
        self.assertEqual(command[1], "--no-replace-objects")
        self.assertEqual(command[2], "--no-lazy-fetch")
        self.assertIn("git@github.com:ExampleUser/safe-project.git", command)
        self.assertNotIn("HEAD", command)
        self.assertNotIn("origin", command)
        self.assertRegex(command[-1], r"^[0-9a-f]{40,64}:refs/heads/main$")
        push_env = kwargs.get("env_overrides")
        self.assertIsInstance(push_env, dict)
        self.assertEqual({key: push_env[key] for key in core.SAFE_PUSH_ENV}, core.SAFE_PUSH_ENV)
        self.assertTrue(str(push_env["GIT_OBJECT_DIRECTORY"]).endswith("/.git/objects"))
        self.assertEqual(core.SAFE_PUSH_ENV["GIT_CONFIG_GLOBAL"], "/dev/null")
        self.assertEqual(core.SAFE_PUSH_ENV["GIT_CONFIG_SYSTEM"], "/dev/null")
        self.assertEqual(core.SAFE_PUSH_ENV["GIT_CONFIG_NOSYSTEM"], "1")

    def test_new_project_race_cannot_inject_unreviewed_parent_history(self) -> None:
        (self.project / "README.md").write_text("safe\n", encoding="utf-8")
        project = self.register()
        plan = self.preflight(project["id"])
        self.assertTrue(plan["ready"])
        original_claim = core._claim_plan

        def inject_history(plan_id: str) -> None:
            original_claim(plan_id)
            subprocess.run([core._git_executable(), "-C", str(self.project), "init", "-b", "main"], check=True, capture_output=True)
            subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.name", "Attacker"], check=True)
            subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.email", "attacker@example.invalid"], check=True)
            hidden = self.project / "private-notes.txt"
            hidden.write_text("unreviewed private history\n", encoding="utf-8")
            subprocess.run([core._git_executable(), "-C", str(self.project), "add", "private-notes.txt"], check=True)
            subprocess.run([core._git_executable(), "-C", str(self.project), "commit", "-m", "hidden parent"], check=True, capture_output=True)
            hidden.unlink()

        with mock.patch.object(core, "github_owner", return_value="ExampleUser"), mock.patch.object(
            core, "_repo_view", return_value=None
        ), mock.patch.object(core, "_gh_executable", return_value="/usr/bin/true"), mock.patch.object(
            core, "_claim_plan", side_effect=inject_history
        ):
            with self.assertRaisesRegex(core.UploadError, "已有 Git 历史"):
                core.execute_upload(plan["plan_id"])

    def test_execute_init_ignores_global_malicious_template(self) -> None:
        template = self.root / "template"
        (template / "info").mkdir(parents=True)
        (template / "info" / "attributes").write_text("*.txt filter=evil\n", encoding="utf-8")
        marker = self.root / "filter-executed"
        global_config = self.root / "global.gitconfig"
        subprocess.run([core._git_executable(), "config", "--file", str(global_config), "user.name", "Test"], check=True)
        subprocess.run(
            [core._git_executable(), "config", "--file", str(global_config), "user.email", "test@example.invalid"],
            check=True,
        )
        subprocess.run(
            [core._git_executable(), "config", "--file", str(global_config), "init.templateDir", str(template)],
            check=True,
        )
        subprocess.run(
            [
                core._git_executable(),
                "config",
                "--file",
                str(global_config),
                "filter.evil.clean",
                f"/usr/bin/touch {marker}; /bin/cat",
            ],
            check=True,
        )
        (self.project / "README.txt").write_text("safe\n", encoding="utf-8")
        project = self.register()
        plan = self.preflight(project["id"])
        self.assertTrue(plan["ready"])
        target = {
            "nameWithOwner": "ExampleUser/safe-project",
            "visibility": "private",
            "url": "https://github.com/ExampleUser/safe-project",
        }
        original = core.run_command
        pushes: list[list[str]] = []

        def fake_network(args: list[str], **kwargs: object) -> core.CommandResult:
            if "push" in args:
                pushes.append(args)
                return core.CommandResult(0, "", "")
            if "ls-remote" in args and pushes:
                oid = pushes[-1][-1].split(":", 1)[0]
                return core.CommandResult(0, f"{oid}\t{args[-1]}\n", "")
            return original(args, **kwargs)

        with mock.patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": str(global_config)}), mock.patch.object(
            core, "github_owner", return_value="ExampleUser"
        ), mock.patch.object(core, "_repo_view", side_effect=[None, target]), mock.patch.object(
            core, "_gh_executable", return_value="/usr/bin/true"
        ), mock.patch.object(core, "run_command", side_effect=fake_network):
            result = core.execute_upload(plan["plan_id"])
        self.assertTrue(result["uploaded"])
        self.assertFalse(marker.exists())
        self.assertFalse((self.project / ".git" / "info" / "attributes").exists())

    def test_history_secret_is_detected_without_exposing_value(self) -> None:
        subprocess.run([core._git_executable(), "-C", str(self.project), "init", "-b", "main"], check=True, capture_output=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.name", "Test"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.email", "test@example.invalid"], check=True)
        secret = synthetic_github_token()
        credential = self.project / "token.txt"
        credential.write_text(secret + "\n", encoding="utf-8")
        subprocess.run([core._git_executable(), "-C", str(self.project), "add", "token.txt"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "commit", "-m", "add"], check=True, capture_output=True)
        credential.unlink()
        subprocess.run([core._git_executable(), "-C", str(self.project), "add", "-A"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "commit", "-m", "remove"], check=True, capture_output=True)
        project = self.register()
        result = self.preflight(project["id"])
        self.assertFalse(result["ready"])
        self.assertIn("history_github_token", {issue["code"] for issue in result["issues"]})
        self.assertNotIn(secret, json.dumps(result))

    def test_binary_history_secret_is_detected(self) -> None:
        subprocess.run([core._git_executable(), "-C", str(self.project), "init", "-b", "main"], check=True, capture_output=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.name", "Test"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.email", "test@example.invalid"], check=True)
        secret = synthetic_github_token().encode()
        payload = self.project / "payload.bin"
        payload.write_bytes(b"\x00" * 16 + secret)
        subprocess.run([core._git_executable(), "-C", str(self.project), "add", "payload.bin"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "commit", "-m", "binary"], check=True, capture_output=True)
        project = self.register()
        result = self.preflight(project["id"])
        self.assertFalse(result["ready"])
        self.assertIn("history_github_token", {issue["code"] for issue in result["issues"]})
        self.assertNotIn(secret.decode(), json.dumps(result))

    def test_history_sensitive_path_alias_is_detected(self) -> None:
        subprocess.run([core._git_executable(), "-C", str(self.project), "init", "-b", "main"], check=True, capture_output=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.name", "Test"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.email", "test@example.invalid"], check=True)
        readme = self.project / "README.md"
        readme.write_text("PASSWORD=short\n", encoding="utf-8")
        subprocess.run([core._git_executable(), "-C", str(self.project), "add", "README.md"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "commit", "-m", "safe name"], check=True, capture_output=True)
        environment = self.project / ".env"
        environment.write_bytes(readme.read_bytes())
        subprocess.run([core._git_executable(), "-C", str(self.project), "add", ".env"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "commit", "-m", "sensitive alias"], check=True, capture_output=True)
        environment.unlink()
        subprocess.run([core._git_executable(), "-C", str(self.project), "add", "-A"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "commit", "-m", "remove alias"], check=True, capture_output=True)
        project = self.register()
        result = self.preflight(project["id"])
        self.assertFalse(result["ready"])
        self.assertIn("history_environment_file", {issue["code"] for issue in result["issues"]})

    def test_deleted_git_credentials_history_is_blocked(self) -> None:
        subprocess.run([core._git_executable(), "-C", str(self.project), "init", "-b", "main"], check=True, capture_output=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.name", "Test"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.email", "test@example.invalid"], check=True)
        credentials = self.project / ".git-credentials"
        credentials.write_text(synthetic_credential_url("OrdinaryPassword12345"), encoding="utf-8")
        subprocess.run([core._git_executable(), "-C", str(self.project), "add", ".git-credentials"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "commit", "-m", "credentials"], check=True, capture_output=True)
        credentials.unlink()
        (self.project / "README.md").write_text("safe\n", encoding="utf-8")
        subprocess.run([core._git_executable(), "-C", str(self.project), "add", "-A"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "commit", "-m", "remove"], check=True, capture_output=True)
        project = self.register()
        result = self.preflight(project["id"])
        self.assertFalse(result["ready"])
        self.assertIn("history_credential_file", {issue["code"] for issue in result["issues"]})

    def test_secret_in_deleted_history_filename_is_detected_and_redacted(self) -> None:
        subprocess.run([core._git_executable(), "-C", str(self.project), "init", "-b", "main"], check=True, capture_output=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.name", "Test"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.email", "test@example.invalid"], check=True)
        secret = synthetic_github_token()
        named = self.project / f"note-{secret}.txt"
        named.write_text("safe\n", encoding="utf-8")
        subprocess.run([core._git_executable(), "-C", str(self.project), "add", "-A"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "commit", "-m", "named"], check=True, capture_output=True)
        named.unlink()
        (self.project / "README.md").write_text("safe\n", encoding="utf-8")
        subprocess.run([core._git_executable(), "-C", str(self.project), "add", "-A"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "commit", "-m", "remove"], check=True, capture_output=True)
        project = self.register()
        result = self.preflight(project["id"])
        self.assertFalse(result["ready"])
        self.assertIn("history_path_github_token", {issue["code"] for issue in result["issues"]})
        self.assertNotIn(secret, json.dumps(result))

    def test_remote_branch_verification_preserves_ref_case(self) -> None:
        oid = "a" * 40
        branch = "Feature/X"
        ref = f"refs/heads/{branch}"
        with mock.patch.object(
            core,
            "run_command",
            return_value=core.CommandResult(0, f"{oid.upper()}\t{ref}\n", ""),
        ):
            core._verify_remote_branch(self.root, "git@github.com:ExampleUser/safe-project.git", oid, branch)

    def test_secret_in_branch_name_is_blocked_and_redacted_from_payloads(self) -> None:
        secret = synthetic_github_token()
        subprocess.run([core._git_executable(), "-C", str(self.project), "init", "-b", secret], check=True, capture_output=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.name", "Test"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.email", "test@example.invalid"], check=True)
        (self.project / "README.md").write_text("safe\n", encoding="utf-8")
        subprocess.run([core._git_executable(), "-C", str(self.project), "add", "README.md"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "commit", "-m", "safe"], check=True, capture_output=True)
        project = self.register()
        result = self.preflight(project["id"])
        with mock.patch.object(core, "github_owner", return_value="ExampleUser"):
            listed = core.list_projects()
        self.assertFalse(result["ready"])
        self.assertIn("branch_github_token", {issue["code"] for issue in result["issues"]})
        self.assertNotIn(secret, json.dumps(result))
        self.assertNotIn(secret, json.dumps(listed))

    def test_commit_message_secret_is_detected_without_exposing_value(self) -> None:
        subprocess.run([core._git_executable(), "-C", str(self.project), "init", "-b", "main"], check=True, capture_output=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.name", "Test"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.email", "test@example.invalid"], check=True)
        secret = synthetic_github_token()
        (self.project / "README.md").write_text("safe\n", encoding="utf-8")
        subprocess.run([core._git_executable(), "-C", str(self.project), "add", "README.md"], check=True)
        subprocess.run(
            [core._git_executable(), "-C", str(self.project), "commit", "-m", f"accidental {secret}"],
            check=True,
            capture_output=True,
        )
        project = self.register()
        result = self.preflight(project["id"])
        self.assertFalse(result["ready"])
        self.assertIn("history_github_token", {issue["code"] for issue in result["issues"]})
        self.assertNotIn(secret, json.dumps(result))

    def test_plan_is_one_time_and_detects_changes(self) -> None:
        (self.project / ".gitignore").write_text(".env\n", encoding="utf-8")
        (self.project / "README.md").write_text("safe\n", encoding="utf-8")
        project = self.register()
        first = self.preflight(project["id"])
        self.assertTrue(first["ready"])
        (self.project / "README.md").write_text("changed\n", encoding="utf-8")
        with mock.patch.object(core, "github_owner", return_value="ExampleUser"), mock.patch.dict(
            os.environ, {"UPLOAD_DRY_RUN": "1"}
        ):
            with self.assertRaisesRegex(core.UploadError, "发生了变化"):
                core.execute_upload(first["plan_id"])

        second = self.preflight(project["id"])
        with mock.patch.object(core, "github_owner", return_value="ExampleUser"), mock.patch.object(
            core, "_repo_view", return_value=None
        ), mock.patch.dict(os.environ, {"UPLOAD_DRY_RUN": "1"}):
            result = core.execute_upload(second["plan_id"])
            self.assertTrue(result["dry_run"])
            with self.assertRaisesRegex(core.UploadError, "已经使用"):
                core.execute_upload(second["plan_id"])

    def test_expired_plan_is_rejected_without_consuming_it(self) -> None:
        (self.project / "README.md").write_text("safe\n", encoding="utf-8")
        project = self.register()
        plan = self.preflight(project["id"])
        plans = core._load_plans()
        plans["plans"][plan["plan_id"]]["expires_at"] = 0
        core._write_json(core.PLANS_PATH, plans)

        with self.assertRaisesRegex(core.UploadError, "已过期"):
            core.execute_upload(plan["plan_id"])
        self.assertFalse(core._load_plans()["plans"][plan["plan_id"]]["used"])

    def test_public_plan_requires_exact_owner_repository_confirmation(self) -> None:
        (self.project / "README.md").write_text("safe\n", encoding="utf-8")
        project = self.register()
        with mock.patch.object(core, "github_owner", return_value="ExampleUser"), mock.patch.object(
            core, "_repo_view", return_value=None
        ):
            plan = core.preflight_upload(project["id"], "safe-project", "public")
        self.assertTrue(plan["ready"])

        with self.assertRaisesRegex(core.UploadError, "完整仓库名"):
            core.execute_upload(plan["plan_id"], "ExampleUser/wrong-project")
        self.assertFalse(core._load_plans()["plans"][plan["plan_id"]]["used"])

        with mock.patch.object(core, "github_owner", return_value="ExampleUser"), mock.patch.object(
            core, "_repo_view", return_value=None
        ), mock.patch.dict(os.environ, {"UPLOAD_DRY_RUN": "1"}):
            result = core.execute_upload(plan["plan_id"], "ExampleUser/safe-project")
        self.assertTrue(result["dry_run"])

    def test_fingerprint_detects_same_size_change_with_restored_mtime(self) -> None:
        readme = self.project / "README.md"
        readme.write_text("alpha\n", encoding="utf-8")
        project = self.register()
        plan = self.preflight(project["id"])
        original_stat = readme.stat()
        readme.write_text("bravo\n", encoding="utf-8")
        os.utime(readme, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
        with mock.patch.object(core, "github_owner", return_value="ExampleUser"), mock.patch.dict(
            os.environ, {"UPLOAD_DRY_RUN": "1"}
        ):
            with self.assertRaisesRegex(core.UploadError, "发生了变化"):
                core.execute_upload(plan["plan_id"])

    def test_fingerprint_detects_executable_bit_change(self) -> None:
        script = self.project / "run.sh"
        script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        script.chmod(0o644)
        project = self.register()
        plan = self.preflight(project["id"])
        self.assertTrue(plan["ready"])
        script.chmod(0o755)
        with mock.patch.object(core, "github_owner", return_value="ExampleUser"), mock.patch.dict(
            os.environ, {"UPLOAD_DRY_RUN": "1"}
        ):
            with self.assertRaisesRegex(core.UploadError, "发生了变化"):
                core.execute_upload(plan["plan_id"])

    def test_core_filemode_false_cannot_hide_mode_mismatch(self) -> None:
        subprocess.run([core._git_executable(), "-C", str(self.project), "init", "-b", "main"], check=True, capture_output=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.name", "Test"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "user.email", "test@example.invalid"], check=True)
        script = self.project / "run.sh"
        script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        script.chmod(0o644)
        subprocess.run([core._git_executable(), "-C", str(self.project), "add", "run.sh"], check=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "commit", "-m", "script"], check=True, capture_output=True)
        subprocess.run([core._git_executable(), "-C", str(self.project), "config", "core.fileMode", "false"], check=True)
        script.chmod(0o755)
        project = self.register()
        result = self.preflight(project["id"])
        self.assertFalse(result["ready"])
        self.assertIn("git_mode_mismatch", {issue["code"] for issue in result["issues"]})


if __name__ == "__main__":
    unittest.main()
