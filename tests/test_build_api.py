#!/usr/bin/env python3
"""Contracts for the immutable, verified DOGG static API projection."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import unittest
import uuid


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import build_api as B


def git(repo, *args, input_text=None, env=None):
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        input=input_text,
        text=True,
        capture_output=True,
        check=True,
        env=env,
    )
    return result.stdout.strip()


class Fixture:
    def __init__(self, name):
        self.root = ROOT / ".test-work" / f"{name}-{uuid.uuid4().hex}"
        self.repo = self.root / "dogg"
        self.output = self.root / "api"
        self.rapp, _ = B.load_verifier()
        self.ticks = []
        self.world = []

    def create(self, world_tick_frames=None, sealed=True, count=3, world_values=None):
        self.repo.mkdir(parents=True)
        git(self.repo, "init", "-q", "-b", "main")
        git(self.repo, "config", "user.name", "dogg-api-tests")
        git(self.repo, "config", "user.email", "dogg-api-tests@example.invalid")
        git(self.repo, "remote", "add", "origin", B.SOURCE_REPOSITORY)
        self.ticks = self.make_frames(
            "tick.anchor",
            "tick:@kody-w/global",
            [
                {"tick": seq, "beat_utc": f"2026-09-18T00:{seq:02d}:00.000Z"}
                for seq in range(count)
            ],
        )
        tick_frames = world_tick_frames or [frame["frame_hash"] for frame in self.ticks]
        if world_values is None:
            world_values = lambda seq: {
                "btc_usd": {"spot": str(100 + seq)},
                "scalar": seq,
            }
        self.world = self.make_frames(
            "world.snapshot",
            "world:@kody-w/dogg",
            [
                {
                    "tick": seq,
                    "tick_frame": tick_frames[seq],
                    "fetched_utc": f"2026-09-18T00:{seq:02d}:01.000Z",
                    "world": world_values(seq),
                    "sources_failed": [],
                }
                for seq in range(count)
            ],
        )
        self.write_chain("ticks", "tick:@kody-w/global", self.ticks, sealed=sealed)
        self.write_chain("world", "world:@kody-w/dogg", self.world, sealed=sealed)
        (self.repo / "PROTOCOL.md").write_text("# fixture\n")
        return self.commit("fixture")

    def make_frames(self, kind, stream, payloads):
        frames = []
        for seq, payload in enumerate(payloads):
            frames.append(
                self.rapp.build_frame(
                    kind,
                    stream,
                    seq,
                    f"2026-09-18T00:0{seq}:00.000Z",
                    payload,
                    frames[-1]["payload_hash"] if frames else None,
                )
            )
        return frames

    def write_chain(self, name, stream, frames, sealed=True):
        directory = self.repo / name
        if directory.exists():
            shutil.rmtree(directory)
        directory.mkdir()
        epoch_size = 2
        sealed_epochs = 1 if sealed else 0
        if sealed_epochs:
            epochs = directory / "epochs"
            epochs.mkdir()
            raw = b"\n".join(B.canonical(frame) for frame in frames[:epoch_size]) + b"\n"
            (epochs / "0.jsonl").write_bytes(raw)
        for frame in frames[sealed_epochs * epoch_size :]:
            (directory / f"{frame['seq']}.json").write_text(
                json.dumps(frame, ensure_ascii=False, indent=2) + "\n"
            )
        (directory / "HEAD.json").write_text(
            json.dumps(
                {
                    "count": len(frames),
                    "stream_id": stream,
                    "head_frame": frames[-1]["frame_hash"],
                    "updated": frames[-1]["utc"],
                    "epoch_size": epoch_size,
                    "sealed_epochs": sealed_epochs,
                },
                indent=2,
            )
            + "\n"
        )

    def commit(self, message):
        git(self.repo, "add", ".")
        env = os.environ.copy()
        env.update(
            {
                "GIT_AUTHOR_DATE": "2026-09-18T00:10:00Z",
                "GIT_COMMITTER_DATE": "2026-09-18T00:10:00Z",
            }
        )
        git(self.repo, "commit", "-q", "-m", message, env=env)
        commit = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "update-ref", B.CANONICAL_REF, commit)
        return commit, git(self.repo, "rev-parse", f"{commit}^{{tree}}")

    def select(self):
        commit = git(self.repo, "rev-parse", "HEAD")
        return commit, git(self.repo, "rev-parse", f"{commit}^{{tree}}")

    def build(self):
        commit, tree = self.select()
        docs = B.build_documents(
            self.repo,
            commit,
            tree,
            commit,
            self.output / "index.json",
        )
        return B.regenerate(self.output, docs), docs

    def rewrite_invalid_ticks(self, mode):
        frames = self.make_frames(
            "tick.anchor",
            "tick:@kody-w/global",
            [{"tick": seq} for seq in range(3)],
        )
        if mode == "genesis":
            frames[0]["prev"] = "0" * 64
            self.rehash(frames[0])
        elif mode == "gap":
            frames[1]["seq"] = 2
            frames[1]["payload"]["tick"] = 2
            frames[1]["payload_hash"] = self.rapp.H("rapp/1:particle", frames[1]["payload"])
            self.rehash(frames[1])
        elif mode == "fork":
            frames[1]["prev"] = "0" * 64
            self.rehash(frames[1])
        else:
            raise AssertionError(mode)
        self.write_chain("ticks", "tick:@kody-w/global", frames)
        return self.commit(mode)

    def rehash(self, frame):
        preimage = {key: value for key, value in frame.items() if key not in ("frame_hash", "sig")}
        frame["frame_hash"] = self.rapp.H("rapp/1:wave", preimage)

    def close(self):
        shutil.rmtree(self.root, ignore_errors=True)


class BuildApiTests(unittest.TestCase):
    def fixture(self):
        fixture = Fixture(self._testMethodName)
        self.addCleanup(fixture.close)
        return fixture

    def test_full_provenance_and_actual_tick_binding_cover_sealed_and_flat_storage(self):
        fixture = self.fixture()
        commit, _ = fixture.create()
        state, docs = fixture.build()
        self.assertEqual(state, "updated")
        latest = docs["latest.json"]
        self.assertEqual(latest["schema"], "dogg/0-static-api")
        self.assertEqual(latest["profile"], "dogg/0-static-api-provenance/1")
        self.assertEqual(latest["tick_frame"], latest["tick_source"]["native_frame_hash"])
        self.assertEqual(latest["spine_head"], latest["tick_source"]["native_frame_hash"])
        self.assertEqual(latest["native_source"]["commit"], commit)
        self.assertEqual(latest["native_source"]["storage_path"], "world/2.json")
        self.assertIsNone(latest["native_source"]["storage_line"])
        self.assertRegex(latest["frame_hash"], r"^[0-9a-f]{64}$")

        rows = docs["series/btc_usd.json"]["rows"]
        sealed = rows[0]
        self.assertEqual(sealed["frame"], sealed["frame_hash"])
        self.assertEqual(len(sealed["frame"]), 64)
        self.assertEqual(sealed["native_source"]["native_seq"], 0)
        self.assertEqual(sealed["native_source"]["native_stream_id"], "world:@kody-w/dogg")
        self.assertEqual(sealed["native_source"]["storage_path"], "world/epochs/0.jsonl")
        self.assertEqual(sealed["native_source"]["storage_line"], 1)
        raw = (fixture.repo / "world/epochs/0.jsonl").read_bytes().splitlines()[0]
        self.assertEqual(sealed["native_source"]["raw_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(sealed["native_source"]["raw_bytes"], len(raw))
        self.assertEqual(sealed["tick_source"]["native_seq"], sealed["tick"])
        self.assertEqual(sealed["tick_source"]["storage_path"], "ticks/epochs/0.jsonl")
        self.assertEqual(sealed["tick_source"]["storage_line"], 1)
        self.assertEqual(
            sealed["tick_source"]["native_genesis_frame_hash"],
            fixture.ticks[0]["frame_hash"],
        )

        coverage = docs["series/btc_usd.json"]["coverage"]
        self.assertEqual(coverage["returned_rows"], 3)
        self.assertEqual(coverage["total_matching_rows"], 3)
        self.assertEqual(coverage["omitted_rows"], 0)
        self.assertEqual(
            docs["index.json"]["input_fingerprint"],
            docs["latest.json"]["input_fingerprint"],
        )

    def test_wrong_or_stale_tick_frame_refuses(self):
        for wrong_index in (0, 1):
            with self.subTest(wrong_index=wrong_index):
                fixture = Fixture(f"{self._testMethodName}-{wrong_index}")
                self.addCleanup(fixture.close)
                fixture.repo.mkdir(parents=True)
                git(fixture.repo, "init", "-q", "-b", "main")
                git(fixture.repo, "config", "user.name", "dogg-api-tests")
                git(fixture.repo, "config", "user.email", "dogg-api-tests@example.invalid")
                git(fixture.repo, "remote", "add", "origin", B.SOURCE_REPOSITORY)
                fixture.ticks = fixture.make_frames(
                    "tick.anchor", "tick:@kody-w/global", [{"tick": seq} for seq in range(3)]
                )
                references = [frame["frame_hash"] for frame in fixture.ticks]
                references[wrong_index] = (
                    "0" * 64 if wrong_index == 0 else fixture.ticks[0]["frame_hash"]
                )
                fixture.world = fixture.make_frames(
                    "world.snapshot",
                    "world:@kody-w/dogg",
                    [
                        {
                            "tick": seq,
                            "tick_frame": references[seq],
                            "fetched_utc": f"2026-09-18T00:0{seq}:01.000Z",
                            "world": {"value": seq},
                            "sources_failed": [],
                        }
                        for seq in range(3)
                    ],
                )
                fixture.write_chain("ticks", "tick:@kody-w/global", fixture.ticks)
                fixture.write_chain("world", "world:@kody-w/dogg", fixture.world)
                commit, tree = fixture.commit("bad tick reference")
                with self.assertRaisesRegex(ValueError, "wrong or stale tick_frame"):
                    B.build_documents(fixture.repo, commit, tree, commit)

    def test_native_genesis_gap_and_fork_refuse(self):
        for mode, message in (
            ("genesis", "genesis"),
            ("gap", "sequence gap"),
            ("fork", "prev"),
        ):
            with self.subTest(mode=mode):
                fixture = Fixture(f"{self._testMethodName}-{mode}")
                self.addCleanup(fixture.close)
                fixture.create()
                commit, tree = fixture.rewrite_invalid_ticks(mode)
                with self.assertRaisesRegex(ValueError, message):
                    B.build_documents(fixture.repo, commit, tree, commit)

    def test_valid_native_history_replacement_refuses_against_previous_projection(self):
        fixture = self.fixture()
        fixture.create()
        fixture.build()

        fixture.ticks = fixture.make_frames(
            "tick.anchor",
            "tick:@kody-w/global",
            [{"tick": 0, "replacement": True}, {"tick": 1}, {"tick": 2}],
        )
        fixture.world = fixture.make_frames(
            "world.snapshot",
            "world:@kody-w/dogg",
            [
                {
                    "tick": seq,
                    "tick_frame": fixture.ticks[seq]["frame_hash"],
                    "fetched_utc": f"2026-09-18T00:0{seq}:01.000Z",
                    "world": {"value": seq},
                    "sources_failed": [],
                }
                for seq in range(3)
            ],
        )
        fixture.write_chain("ticks", "tick:@kody-w/global", fixture.ticks)
        fixture.write_chain("world", "world:@kody-w/dogg", fixture.world)
        commit, tree = fixture.commit("replace native genesis")
        with self.assertRaisesRegex(ValueError, "genesis changed"):
            B.build_documents(
                fixture.repo,
                commit,
                tree,
                commit,
                fixture.output / "index.json",
            )

    def test_valid_native_fork_and_canonical_history_replacement_refuse(self):
        forked = Fixture(f"{self._testMethodName}-fork")
        self.addCleanup(forked.close)
        forked.create()
        forked.build()
        original_genesis = forked.ticks[0]
        changed_tail = [original_genesis]
        for seq in (1, 2):
            payload = {"tick": seq, "fork": True}
            changed_tail.append(
                forked.rapp.build_frame(
                    "tick.anchor",
                    "tick:@kody-w/global",
                    seq,
                    f"2026-09-18T00:0{seq}:00.000Z",
                    payload,
                    changed_tail[-1]["payload_hash"],
                )
            )
        forked.ticks = changed_tail
        forked.world = forked.make_frames(
            "world.snapshot",
            "world:@kody-w/dogg",
            [
                {
                    "tick": seq,
                    "tick_frame": forked.ticks[seq]["frame_hash"],
                    "fetched_utc": f"2026-09-18T00:0{seq}:01.000Z",
                    "world": {"value": seq},
                    "sources_failed": [],
                }
                for seq in range(3)
            ],
        )
        forked.write_chain("ticks", "tick:@kody-w/global", forked.ticks)
        forked.write_chain("world", "world:@kody-w/dogg", forked.world)
        commit, tree = forked.commit("valid rewritten fork")
        with self.assertRaisesRegex(ValueError, "fork at previously accepted head"):
            B.build_documents(
                forked.repo,
                commit,
                tree,
                commit,
                forked.output / "index.json",
            )

        replaced = Fixture(f"{self._testMethodName}-commit")
        self.addCleanup(replaced.close)
        replaced.create()
        replaced.build()
        git(replaced.repo, "checkout", "-q", "--orphan", "replacement-main")
        git(replaced.repo, "add", ".")
        env = {
            **os.environ,
            "GIT_AUTHOR_DATE": "2026-09-18T00:12:00Z",
            "GIT_COMMITTER_DATE": "2026-09-18T00:12:00Z",
        }
        git(replaced.repo, "commit", "-q", "-m", "replacement history", env=env)
        commit, tree = replaced.select()
        git(replaced.repo, "update-ref", B.CANONICAL_REF, commit)
        with self.assertRaisesRegex(ValueError, "commit rollback or replacement"):
            B.build_documents(
                replaced.repo,
                commit,
                tree,
                commit,
                replaced.output / "index.json",
            )

    def test_every_prior_semantic_frame_is_checked_even_when_heads_match(self):
        fixture = self.fixture()
        fixture.create(sealed=False, count=4)
        fixture.build()
        old_tick_head = fixture.ticks[-1]["frame_hash"]
        old_world_head = fixture.world[-1]["frame_hash"]

        fixture.world[1]["payload"]["world"]["scalar"] = 999
        fixture.world[1]["payload_hash"] = fixture.rapp.H(
            "rapp/1:particle", fixture.world[1]["payload"]
        )
        fixture.rehash(fixture.world[1])
        fixture.world[2]["prev"] = fixture.world[1]["payload_hash"]
        fixture.rehash(fixture.world[2])

        self.assertEqual(fixture.ticks[-1]["frame_hash"], old_tick_head)
        self.assertEqual(fixture.world[-1]["frame_hash"], old_world_head)
        fixture.write_chain("ticks", "tick:@kody-w/global", fixture.ticks)
        fixture.write_chain("world", "world:@kody-w/dogg", fixture.world)
        commit, tree = fixture.commit("rewrite middle history and compact")
        with self.assertRaisesRegex(
            ValueError, "semantic frame changed at previously accepted sequence 1"
        ):
            B.build_documents(
                fixture.repo,
                commit,
                tree,
                commit,
                fixture.output / "index.json",
            )

    def test_flat_to_sealed_compaction_preserves_semantic_prefix(self):
        fixture = self.fixture()
        fixture.create(sealed=False)
        fixture.build()
        fixture.write_chain("ticks", "tick:@kody-w/global", fixture.ticks, sealed=True)
        fixture.write_chain("world", "world:@kody-w/dogg", fixture.world, sealed=True)
        commit, tree = fixture.commit("compact native storage")

        documents = B.build_documents(
            fixture.repo,
            commit,
            tree,
            commit,
            fixture.output / "index.json",
        )
        self.assertEqual(
            documents["series/btc_usd.json"]["rows"][0]["native_source"]["storage_path"],
            "world/epochs/0.jsonl",
        )
        self.assertEqual(
            documents["series/btc_usd.json"]["rows"][0]["tick_source"]["storage_path"],
            "ticks/epochs/0.jsonl",
        )

    def test_prior_storage_provenance_is_reconstructed_and_verified(self):
        fixture = self.fixture()
        fixture.create()
        fixture.build()
        index_path = fixture.output / "index.json"
        previous = json.loads(index_path.read_text())
        previous["verified_inputs"]["chains"]["world"]["records_fingerprint"] = "0" * 64
        previous["input_fingerprint"] = B.fingerprint(previous["verified_inputs"])
        index_path.write_text(json.dumps(previous) + "\n")
        commit, tree = fixture.select()

        with self.assertRaisesRegex(ValueError, "world storage provenance mismatch"):
            B.build_documents(
                fixture.repo,
                commit,
                tree,
                commit,
                index_path,
            )

    def test_commit_replacement_and_tree_substitution_refuse(self):
        fixture = self.fixture()
        commit, tree = fixture.create()
        replacement = git(
            fixture.repo,
            "commit-tree",
            tree,
            input_text="replacement\n",
            env={
                **os.environ,
                "GIT_AUTHOR_NAME": "tests",
                "GIT_AUTHOR_EMAIL": "tests@example.invalid",
                "GIT_COMMITTER_NAME": "tests",
                "GIT_COMMITTER_EMAIL": "tests@example.invalid",
                "GIT_AUTHOR_DATE": "2026-09-18T00:11:00Z",
                "GIT_COMMITTER_DATE": "2026-09-18T00:11:00Z",
            },
        )
        git(fixture.repo, "replace", commit, replacement)
        with self.assertRaisesRegex(ValueError, "replacement"):
            B.build_documents(fixture.repo, commit, tree, commit)
        git(fixture.repo, "replace", "-d", commit)
        with self.assertRaisesRegex(ValueError, "tree"):
            B.build_documents(fixture.repo, commit, "0" * 40, commit)

    def test_mutable_worktree_is_not_a_source_and_repeat_is_a_true_noop(self):
        fixture = self.fixture()
        fixture.create()
        state, docs = fixture.build()
        self.assertEqual(state, "updated")
        before = {
            path.relative_to(fixture.output).as_posix(): (path.read_bytes(), path.stat().st_mtime_ns)
            for path in fixture.output.rglob("*")
            if path.is_file()
        }
        (fixture.repo / "world/2.json").write_text('{"attacker":"mutable worktree"}\n')
        time.sleep(0.01)
        state, again = fixture.build()
        self.assertEqual(state, "unchanged")
        self.assertEqual(docs, again)
        after = {
            path.relative_to(fixture.output).as_posix(): (path.read_bytes(), path.stat().st_mtime_ns)
            for path in fixture.output.rglob("*")
            if path.is_file()
        }
        self.assertEqual(before, after)
        self.assertNotIn("attacker", json.dumps(again))

    def test_series_window_is_bounded_and_discloses_exact_omission(self):
        fixture = self.fixture()
        fixture.create()
        original = B.WINDOW
        B.WINDOW = 2
        try:
            _, docs = fixture.build()
        finally:
            B.WINDOW = original
        series = docs["series/btc_usd.json"]
        self.assertEqual([row["native_source"]["native_seq"] for row in series["rows"]], [1, 2])
        self.assertEqual(
            series["coverage"],
            {
                "kind": "rolling-world-frames-containing-source",
                "window_limit": 2,
                "returned_rows": 2,
                "total_matching_rows": 3,
                "omitted_rows": 1,
                "first": {
                    "native_seq": 1,
                    "frame_hash": fixture.world[1]["frame_hash"],
                    "tick": 1,
                    "tick_frame": fixture.ticks[1]["frame_hash"],
                    "utc": "2026-09-18T00:01:01.000Z",
                },
                "last": {
                    "native_seq": 2,
                    "frame_hash": fixture.world[2]["frame_hash"],
                    "tick": 2,
                    "tick_frame": fixture.ticks[2]["frame_hash"],
                    "utc": "2026-09-18T00:02:01.000Z",
                },
            },
        )

    def test_unsafe_world_source_identifiers_refuse_before_path_planning(self):
        for source in (
            "../../escape",
            "nested/name",
            r"nested\name",
            ".",
            "..",
            ".hidden",
            "control\nname",
            "café",
            "cafe\u0301",
            "ｓource",
        ):
            with self.subTest(source=source):
                fixture = Fixture(f"{self._testMethodName}-{uuid.uuid4().hex}")
                self.addCleanup(fixture.close)
                fixture.create(world_values=lambda seq, source=source: {source: seq})
                commit, tree = fixture.select()
                with self.assertRaisesRegex(ValueError, "unsafe world source identifier"):
                    B.build_documents(fixture.repo, commit, tree, commit)
                self.assertFalse((fixture.root / "escape.json").exists())

    def test_case_colliding_world_sources_refuse(self):
        fixture = self.fixture()
        fixture.create(world_values=lambda seq: {"Sensor": seq, "sensor": seq})
        commit, tree = fixture.select()
        with self.assertRaisesRegex(ValueError, "world source identifier collision"):
            B.build_documents(fixture.repo, commit, tree, commit)

    def test_verified_native_dictionary_projection_member_collisions_refuse(self):
        for member in ("frame_hash", "TICK"):
            with self.subTest(member=member):
                fixture = Fixture(f"{self._testMethodName}-{member}")
                self.addCleanup(fixture.close)
                fixture.create(
                    world_values=lambda seq, member=member: {
                        "sensor": {"reading": seq, member: "native-value"}
                    }
                )
                commit, tree = fixture.select()
                with self.assertRaisesRegex(
                    ValueError,
                    rf"native source 'sensor' data member collision: {member!r}",
                ):
                    B.build_documents(fixture.repo, commit, tree, commit)

    def test_output_targets_refuse_traversal_and_normalization_collisions(self):
        fixture = self.fixture()
        with self.assertRaisesRegex(ValueError, "unsafe API document path"):
            B.regenerate(fixture.output, {"../escape.json": {}})
        self.assertFalse((fixture.root / "escape.json").exists())

        with self.assertRaisesRegex(ValueError, "API document path collision"):
            B.regenerate(
                fixture.output,
                {
                    "series/Sensor.json": {},
                    "series/sensor.json": {},
                },
            )

    def test_final_output_symlink_escape_refuses(self):
        fixture = self.fixture()
        fixture.output.mkdir(parents=True)
        outside = fixture.root / "outside"
        outside.mkdir()
        (fixture.output / "series").symlink_to(outside, target_is_directory=True)

        with self.assertRaisesRegex(ValueError, "target escaped output"):
            B.regenerate(fixture.output, {"series/safe.json": {}})
        self.assertFalse((outside / "safe.json").exists())

    def test_projection_never_claims_rapp1_authority(self):
        fixture = self.fixture()
        fixture.create()
        _, docs = fixture.build()
        for value in docs.values():
            self.assertEqual(value["schema"], "dogg/0-static-api")
            self.assertIn("non-authoritative", value["authority"])
            self.assertNotEqual(value["profile"], "rapp/1")
        readme = (ROOT / "README.md").read_text()
        self.assertIn("not RAPP/1", readme)


if __name__ == "__main__":
    unittest.main()
