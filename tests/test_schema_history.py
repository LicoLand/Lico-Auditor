from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from lico_auditor.privacy_rules import parse_repository_policy
from lico_auditor.scanner import scan_history, scan_worktree
from lico_auditor.schema_history import schema_fixture_only, schema_only, source_constant


SQL = b"""-- Synthetic producer output; no user records.
CREATE TABLE events (id TEXT PRIMARY KEY, epoch INTEGER NOT NULL DEFAULT 0);
CREATE TABLE schema_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE INDEX events_epoch ON events(epoch);
INSERT INTO schema_metadata(key,value) VALUES ('version','7');
"""
OLD = "tests/fixtures/schema.sql"
NEW = "tests/fixtures/schema_layout.rs"
NAME = "CAPTURED_SCHEMA"


def constant(payload: bytes) -> bytes:
    return b"// Independently captured producer fixture.\n" + f'pub const {NAME}: &str = r#"'.encode() + payload + b'"#;\n'


class Fixture:
    def __init__(self, root: Path, payload: bytes = SQL):
        self.root = root
        self.env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1",
                        GIT_AUTHOR_NAME="Fixture Author", GIT_AUTHOR_EMAIL="fixture@example.invalid",
                        GIT_COMMITTER_NAME="Fixture Author", GIT_COMMITTER_EMAIL="fixture@example.invalid")
        self.git("init", "-q", "--template=", "-b", "feature/schema-fixture")
        self.write("src/schema.rs", b"pub const SCHEMA_VERSION: u32 = 7;\n")
        self.producer = self.commit("Define synthetic schema producer")
        self.write(OLD, payload)
        self.original = self.commit("Capture synthetic schema fixture")
        (root / OLD).unlink()
        self.write(NEW, constant(payload))
        self.document = {"schemaVersion": 1, "allowedJsonPaths": [], "publicReferenceDomains": [],
                         "reviewedSchemaHistory": [{"path": OLD, "sha256": hashlib.sha256(payload).hexdigest(),
                             "successor": {"path": NEW, "constant": NAME},
                             "producer": {"path": "src/schema.rs", "revision": self.producer},
                             "reason": "Reviewed synthetic producer schema is preserved byte-for-byte in the shared test source."}]}
        self.policy()
        self.head = self.commit("Retain reviewed schema as compiled test source")

    def git(self, *args: str) -> str:
        return subprocess.check_output(["git", *args], cwd=self.root, env=self.env, stderr=subprocess.DEVNULL).decode().strip()

    def write(self, path: str, raw: bytes) -> None:
        file = self.root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(raw)

    def policy(self) -> None:
        self.write(".lico-auditor/policy.json", json.dumps(self.document).encode())

    def commit(self, message: str) -> str:
        self.git("add", ".")
        self.git("commit", "-qm", message)
        return self.git("rev-parse", "HEAD")

    def findings(self):
        return scan_history(self.root, ref=f"{self.producer}..HEAD", profile="common")


class SchemaHistoryTests(unittest.TestCase):
    def test_current_schema_fixture_is_exact_and_definition_only(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            document = {
                "schemaVersion": 1,
                "allowedJsonPaths": [],
                "publicReferenceDomains": [],
                "reviewedSchemaFixtures": [{
                    "path": OLD,
                    "reason": "Synthetic retained-table structure used by deterministic migration coverage.",
                }],
            }
            (root / ".lico-auditor").mkdir()
            (root / ".lico-auditor" / "policy.json").write_text(json.dumps(document))
            (root / "tests" / "fixtures").mkdir(parents=True)
            ddl = b"CREATE TABLE retained(id TEXT PRIMARY KEY);\nCREATE INDEX retained_id ON retained(id);\n"
            (root / OLD).write_bytes(ddl)
            self.assertFalse(scan_worktree(root, profile="common"))
            self.assertTrue(schema_fixture_only(ddl))

            for unsafe in [
                b"INSERT INTO retained(id) VALUES ('row');\n",
                b"DELETE FROM retained;\n",
                b"ATTACH DATABASE 'other.db' AS external;\n",
                b"ALTER TABLE retained ADD COLUMN runtime_value TEXT;\n",
                b"CREATE TRIGGER mutate AFTER UPDATE ON retained BEGIN DELETE FROM retained; END;\n",
            ]:
                with self.subTest(unsafe=unsafe.split()[0]):
                    (root / OLD).write_bytes(ddl + unsafe)
                    self.assertIn("data-file-not-allowed", {item.rule for item in scan_worktree(root, profile="common")})
                    self.assertFalse(schema_fixture_only(ddl + unsafe))

            (root / OLD).write_bytes(ddl)
            other = root / "tests" / "fixtures" / "other.sql"
            other.write_bytes(ddl)
            self.assertIn("data-file-not-allowed", {item.rule for item in scan_worktree(root, profile="common") if item.path == "tests/fixtures/other.sql"})

    def test_current_schema_fixture_declaration_rejects_broad_or_duplicate_paths(self):
        base = {"schemaVersion": 1, "allowedJsonPaths": [], "publicReferenceDomains": []}
        for path in ["tests/fixtures/*.sql", "tests/fixtures/../schema.sql", "exports/schema.sql"]:
            document = dict(base, reviewedSchemaFixtures=[{
                "path": path,
                "reason": "Synthetic retained-table structure used by deterministic migration coverage.",
            }])
            self.assertIsNotNone(parse_repository_policy(json.dumps(document).encode())[1])
        document = dict(base, reviewedSchemaFixtures=[{
            "path": OLD,
            "reason": "Synthetic retained-table structure used by deterministic migration coverage.",
        }] * 2)
        self.assertIsNotNone(parse_repository_policy(json.dumps(document).encode())[1])

    def test_exact_provenance_is_visible_and_text_rules_still_run(self):
        payload = SQL + b"-- Privacy canary: /Users/maintainer/Library/synthetic.json\n"
        with tempfile.TemporaryDirectory() as raw:
            fixture = Fixture(Path(raw), payload)
            observed = fixture.findings()
            self.assertFalse(any(item.rule == "data-file-not-allowed" for item in observed))
            self.assertTrue(any(item.rule == "reviewed-schema-source-history" and item.commit == fixture.original for item in observed))
            self.assertTrue(any(item.rule == "developer-macos-home-path" and item.path == OLD for item in observed))

    def test_current_sql_is_never_admitted(self):
        with tempfile.TemporaryDirectory() as raw:
            fixture = Fixture(Path(raw))
            fixture.write(OLD, SQL)
            self.assertTrue(any(item.rule == "data-file-not-allowed" for item in scan_worktree(fixture.root, profile="common")))
            fixture.commit("Restore the forbidden current SQL form")
            self.assertTrue(any(item.rule == "schema-history-proof-unavailable" for item in fixture.findings()))

    def test_record_payload_cannot_be_admitted_even_with_matching_hash_and_successor(self):
        for extra in [b"INSERT INTO events(id,epoch) VALUES ('synthetic-user',0);\n",
                      b"CREATE TABLE copied(id) AS SELECT ('synthetic-user');\n",
                      b"CREATE TRIGGER capture AFTER UPDATE ON events BEGIN INSERT INTO events VALUES ('synthetic-user',0); END;\n",
                      b"ATTACH DATABASE 'synthetic.db' AS external;\n"]:
            with self.subTest(extra=extra.split()[0]), tempfile.TemporaryDirectory() as raw:
                fixture = Fixture(Path(raw), SQL + extra)
                observed = fixture.findings()
                self.assertTrue(any(item.rule == "schema-history-proof-unavailable" for item in observed))
                self.assertTrue(any(item.rule == "data-file-not-allowed" for item in observed))
                self.assertFalse(any(item.rule == "reviewed-schema-source-history" for item in observed))

    def test_changed_historical_bytes_at_the_same_path_remain_blocked(self):
        with tempfile.TemporaryDirectory() as raw:
            fixture = Fixture(Path(raw))
            fixture.git("checkout", "--detach", fixture.original)
            fixture.write(OLD, SQL.replace(b"DEFAULT 0", b"DEFAULT 1"))
            altered = fixture.commit("Change historical fixture without review")
            (fixture.root / OLD).unlink()
            fixture.write(NEW, constant(SQL))
            fixture.policy()
            fixture.commit("Retain only the reviewed original source bytes")
            observed = fixture.findings()
            self.assertTrue(any(item.rule == "reviewed-schema-source-history" for item in observed))
            self.assertTrue(any(item.rule == "data-file-not-allowed" and item.commit == altered for item in observed))

    def test_uncommitted_successor_cannot_rescue_bad_selected_candidate(self):
        with tempfile.TemporaryDirectory() as raw:
            fixture = Fixture(Path(raw))
            fixture.write(NEW, constant(SQL + b"-- changed\n"))
            fixture.commit("Change committed source successor")
            fixture.write(NEW, constant(SQL))
            self.assertTrue(any(item.rule == "schema-history-proof-unavailable" for item in fixture.findings()))

    def test_producer_path_revision_and_regular_successor_are_required(self):
        for mutation in ["missing-producer", "missing-revision", "symlink-successor"]:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw:
                fixture = Fixture(Path(raw))
                declaration = fixture.document["reviewedSchemaHistory"][0]
                if mutation == "missing-producer":
                    declaration["producer"]["path"] = "src/absent.rs"
                elif mutation == "missing-revision":
                    declaration["producer"]["revision"] = "0" * 40
                else:
                    (fixture.root / NEW).unlink()
                    (fixture.root / NEW).symlink_to("../../../outside.rs")
                fixture.policy()
                fixture.commit("Introduce an invalid proof boundary")
                self.assertTrue(any(item.rule == "schema-history-proof-unavailable" for item in fixture.findings()))

    def test_declarations_cannot_name_globs_exports_or_ambiguous_entries(self):
        with tempfile.TemporaryDirectory() as raw:
            fixture = Fixture(Path(raw))
            for path in ["tests/fixtures/*.sql", "tests/fixtures/../private.sql", "exports/schema.sql"]:
                fixture.document["reviewedSchemaHistory"][0]["path"] = path
                _, error = parse_repository_policy(json.dumps(fixture.document).encode())
                self.assertIsNotNone(error)
            fixture.document["reviewedSchemaHistory"][0]["path"] = OLD
            fixture.document["reviewedSchemaHistory"] *= 2
            _, error = parse_repository_policy(json.dumps(fixture.document).encode())
            self.assertIsNotNone(error)

    def test_source_successor_is_a_real_single_constant_not_a_matched_string(self):
        source = constant(SQL)
        self.assertEqual(source_constant(source, NAME), SQL)
        for raw in [b"/*" + source + b"*/", b"#[cfg(any())]\n" + source,
                    source + source, b"// " + source.replace(b"\n", b" ")]:
            self.assertIsNone(source_constant(raw, NAME))

    def test_counter_trigger_and_schema_marker_are_source_but_other_rows_refuse(self):
        trigger = b"""CREATE TRIGGER bump AFTER UPDATE OF id ON events FOR EACH ROW
WHEN NEW.epoch = OLD.epoch BEGIN UPDATE events SET epoch = OLD.epoch + 1 WHERE id = NEW.id; END;
"""
        self.assertTrue(schema_only(SQL + trigger))
        changed = b"""CREATE INDEX event_work ON events(id) WHERE id LIKE 'work:%:pending';
CREATE TRIGGER bump_changed AFTER UPDATE OF id ON events WHEN (OLD.id IS NOT NEW.id)
BEGIN UPDATE events SET epoch = epoch + 1 WHERE id = NEW.id; END;
"""
        self.assertTrue(schema_only(SQL + changed))
        self.assertFalse(schema_only(SQL + changed.replace(b"epoch = epoch + 1", b"epoch = 123456")))
        self.assertFalse(schema_only(SQL + b"INSERT INTO schema_metadata(key,value) VALUES ('user','synthetic');\n"))
        self.assertFalse(schema_only(SQL + b"DELETE FROM events;\n"))

    def test_actual_cli_reports_proof_without_accepting_changed_content(self):
        with tempfile.TemporaryDirectory() as raw:
            fixture = Fixture(Path(raw))
            tool = Path(__file__).resolve().parents[1] / "bin/lico-auditor"
            command = ["bash", str(tool), "report", "--repo", str(fixture.root), "--profile", "common", "--history", "--ref", f"{fixture.producer}..HEAD", "--format", "json"]
            result = subprocess.run(command, capture_output=True, env=fixture.env, check=False)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            report = json.loads(result.stdout)
            self.assertTrue(any(item["rule"] == "reviewed-schema-source-history" for item in report["findings"]))
            fixture.write(NEW, constant(SQL + b"-- unreviewed\n"))
            fixture.commit("Change the selected source")
            result = subprocess.run(command, capture_output=True, env=fixture.env, check=False)
            self.assertEqual(result.returncode, 1)
            self.assertIn("schema-history-proof-unavailable", {item["rule"] for item in json.loads(result.stdout)["findings"]})

    def test_unread_history_is_not_an_empty_successful_review(self):
        with tempfile.TemporaryDirectory() as raw:
            fixture = Fixture(Path(raw))
            with patch("lico_auditor.scanner._cat_blob_batch", return_value=[]):
                observed = fixture.findings()
            self.assertTrue(any(item.rule == "git-history-content-unavailable" and item.severity == "error" for item in observed))
            self.assertFalse(any(item.rule == "reviewed-schema-source-history" for item in observed))


if __name__ == "__main__":
    unittest.main()
