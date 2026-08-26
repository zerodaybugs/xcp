#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_gate(repo: Path, results: Path) -> None:
    inode = repo / "vm/devices/virtio/virtiofs/src/inode.rs"
    text = inode.read_text(encoding="utf-8")
    start = text.find("fn child_path(")
    if start < 0:
        raise SystemExit("child_path missing")
    block = text[start : start + 2600]
    checks = {
        "path_push_present": "path.push(name.as_ref())" in block,
        "parent_lstat_absent": "lstat(&*self.get_path())" not in block,
        "canonicalize_absent": "canonicalize" not in block.lower(),
        "resolve_beneath_absent": "resolve_beneath" not in block.lower(),
    }
    commit = (results / "SOURCE_COMMIT.txt").read_text(encoding="utf-8").strip()
    report = {
        "schema": "openvmm-child-path-current-source-v3",
        "commit": commit,
        "inode_sha256": sha256(inode),
        "checks": checks,
        "pass": all(checks.values()),
        "excerpt": block[:1800],
    }
    (results / "SOURCE_CHILD_PATH_GATE.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )


def append_tests(repo: Path, tests_file: Path) -> None:
    target = repo / "vm/devices/virtio/virtiofs/src/integration_tests.rs"
    text = target.read_text(encoding="utf-8")
    marker = "audit_windows_raw_symlink_parent_reads_outside_share"
    if marker in text:
        raise SystemExit("Windows audit tests already present")
    target.write_text(
        text.rstrip() + "\n" + tests_file.read_text(encoding="utf-8"),
        encoding="utf-8",
    )


def apply_fixed_control(repo: Path) -> None:
    inode = repo / "vm/devices/virtio/virtiofs/src/inode.rs"
    text = inode.read_text(encoding="utf-8")
    anchor = (
        "    /// Appends a child name to this inode's path.\n"
        "    fn child_path(&self, name: &LxStr) -> lx::Result<PathBuf> {\n"
    )
    if anchor not in text:
        raise SystemExit("child_path anchor missing")
    replacement = anchor + (
        "        // Minimal kill control only. A production fix should also use\n"
        "        // descriptor-relative root confinement for all child operations.\n"
        "        let parent_stat = self.volume.lstat(&*self.get_path())?;\n"
        "        if parent_stat.mode & lx::S_IFMT != lx::S_IFDIR {\n"
        "            return Err(lx::Error::ENOTDIR);\n"
        "        }\n\n"
    )
    inode.write_text(text.replace(anchor, replacement, 1), encoding="utf-8")

    tests = repo / "vm/devices/virtio/virtiofs/src/integration_tests.rs"
    text = tests.read_text(encoding="utf-8")
    read_old = (
        "    assert_eq!(\n"
        "        header.error, 0,\n"
        "        \"vulnerable Windows backend should resolve below symlink inode\"\n"
        "    );\n"
        "    let outside_entry: fuse_entry_out = harness.read_response(resp_gpa);\n"
    )
    read_new = (
        "    assert_eq!(\n"
        "        header.error,\n"
        "        -(lx::Error::ENOTDIR.value()),\n"
        "        \"fixed Windows backend must reject a symlink nodeid as a directory parent\"\n"
        "    );\n"
        "    assert_eq!(\n"
        "        std::fs::read(outside.path().join(\"host-secret.txt\")).unwrap(),\n"
        "        secret\n"
        "    );\n"
        "    return;\n"
        "    #[allow(unreachable_code)]\n"
        "    let outside_entry: fuse_entry_out = harness.read_response(resp_gpa);\n"
    )
    if read_old not in text:
        raise SystemExit("read control anchor missing")
    text = text.replace(read_old, read_new, 1)

    write_old = (
        "    assert_eq!(\n"
        "        header.error, 0,\n"
        "        \"vulnerable Windows backend should create below symlink inode\"\n"
        "    );\n"
        "    let create_out: fuse::CreateOut = harness.read_response(resp_gpa);\n"
    )
    write_new = (
        "    assert_eq!(\n"
        "        header.error,\n"
        "        -(lx::Error::ENOTDIR.value()),\n"
        "        \"fixed Windows backend must reject create below a symlink nodeid\"\n"
        "    );\n"
        "    assert!(\n"
        "        !outside.path().join(\"guest-created.txt\").exists(),\n"
        "        \"fixed source must not create the outside file\"\n"
        "    );\n"
        "    return;\n"
        "    #[allow(unreachable_code)]\n"
        "    let create_out: fuse::CreateOut = harness.read_response(resp_gpa);\n"
    )
    if write_old not in text:
        raise SystemExit("write control anchor missing")
    tests.write_text(text.replace(write_old, write_new, 1), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--mode", choices=("vulnerable", "fixed"), required=True)
    args = parser.parse_args()

    args.results.mkdir(parents=True, exist_ok=True)
    if args.mode == "vulnerable":
        source_gate(args.repo, args.results)
        append_tests(args.repo, args.tests)
    else:
        apply_fixed_control(args.repo)


if __name__ == "__main__":
    main()
