# dogg-api

Free static JSON over the native DOGG network:

- Latest: <https://raw.githubusercontent.com/kody-w/dogg-api/main/api/latest.json>
- Directory: <https://raw.githubusercontent.com/kody-w/dogg-api/main/api/index.json>
- Bounded series: `api/series/<source>.json`

This repository is an auditable, **non-authoritative** `dogg/0-static-api`
convenience projection. It is not RAPP/1 and does not modify, replace, or
relabel native DOGG history.

## Provenance profile

`dogg/0-static-api-provenance/1` is emitted in latest, index, and series
documents. Every value row binds:

- the complete 64-hex native world frame hash, stream, sequence, genesis, and UTC;
- the immutable `kody-w/dogg` commit and exact flat-file or sealed-epoch
  storage path/line, plus SHA-256 and byte length of the exact stored record;
- the payload's actual `tick` and `tick_frame`; and
- the same complete tuple for the independently verified referenced tick.

For sealed JSONL records, raw bytes exclude the single LF record delimiter. For
flat records, raw bytes are the complete file. `latest.json` retains
`spine_head` only as a deprecated alias of the actual
`tick_source.native_frame_hash`; it never substitutes a newer ticks head.
The tuple shape aligns with DOGG's forward bridge, but this unsigned static
view does not inherit that bridge's signatures or authority.

`input_fingerprint` hashes the versioned source commit/tree/main binding,
pinned verifier provenance, both verified chain heads/geneses, and
fingerprints of every exact raw record tuple. Series disclose their rolling
limit, returned range, total matching rows, and omitted count. `built_utc` is
the immutable source commit time, so rebuilding identical inputs is byte-for-byte
unchanged.

## Build and verification

The builder requires explicit full commit, tree, and canonical `origin/main`
commit IDs. It rejects the wrong origin, shallow history, grafts, replacement
refs, non-main ancestry, tree substitution, native gaps/forks/genesis changes,
hash failures, historical changes at every previously accepted sequence, and
wrong/stale tick references. Flat-to-sealed compaction is accepted only when
the semantic native frames are byte-identical; old and new storage provenance
is verified independently. Source bytes come from Git objects, never the
mutable worktree.

World source identifiers use a bounded ASCII alphanumeric/underscore/hyphen
grammar. Output planning rejects separators, dot segments, Unicode ambiguity,
case-normalization collisions, reserved filenames, symlinks, and any target
that does not remain beneath the selected output directory. Dictionary-valued
native source data cannot shadow projection or provenance members, including
after NFC and case normalization.

Before writing output, the builder runs the byte-pinned native DOGG
`tools/verify_thread.py` oracle over both source chains using DOGG's
`HEAD.json` + sealed epochs + flat-tail `chainio` contract. Exact public
verifier bytes and MIT license are in `vendor/dogg-native-verifier/`, with
their source commit, tree, hashes, and lengths in `PROVENANCE.json`.

```sh
python3 -B -m unittest discover -s tests -v

SOURCE_COMMIT="$(git -C PATH_TO_DOGG rev-parse refs/remotes/origin/main^{commit})"
SOURCE_TREE="$(git -C PATH_TO_DOGG rev-parse "$SOURCE_COMMIT^{tree}")"
python3 -B tools/build_api.py \
  --source-repo PATH_TO_DOGG \
  --source-commit "$SOURCE_COMMIT" \
  --source-tree "$SOURCE_TREE" \
  --source-main-commit "$SOURCE_COMMIT"
```

The native chains remain the complete record. Series here are bounded rolling
windows and are never evidence of signature authority, writer authenticity, or
current network truth.
