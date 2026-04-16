#!/usr/bin/env python3
"""扫描 repos/ 目录，索引高置信度 C/C++ 原生恶意二进制。

安全约束：
- 不执行任何样本
- 不调用 ldd
- 不运行任何二进制
- 仅调用 `file -b` 和 `strings -a` 做静态判定
- 仅解压已知压缩格式；未知压缩包不解压
"""

from __future__ import annotations

import argparse
import csv
import os
import shutil
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parents[1]
REPOS_DIR = REPO_ROOT / "repos"
OUTPUTS_DIR = REPO_ROOT / "outputs"
SEVENZ_ARCHIVE = REPO_ROOT / "7z2600-linux-x64.tar.xz"
SEVENZ_DIR = REPO_ROOT / ".tools" / "7z2600"
SCAN_TIMEOUT_SEC = 5
STRINGS_TIMEOUT_SEC = 12
MAX_FILE_SIZE = 100 * 1024 * 1024

NATIVE_MARKERS = ("ELF", "PE32", "PE32+", "DLL")
EXCLUDE_MARKERS = (
    ".NET",
    "CLR",
    "Mono",
    "MSIL",
    "mscoree",
    "Java",
    "class",
    "jar",
    "Go build ID",
    "rustc",
    "Cargo",
    "Rust",
)
CPP_MARKERS = (
    "GCC",
    "GLIBC",
    "libstdc++",
    "libc.so",
    "MSVC",
    "msvcrt",
    "vcruntime",
    "MinGW",
)
KNOWN_ARCHIVE_SUFFIXES = {
    ".zip",
    ".7z",
    ".rar",
    ".cab",
    ".tar",
    ".gz",
    ".tgz",
    ".bz2",
    ".xz",
}
FILE_CMD_AVAILABLE = shutil.which("file") is not None


@dataclass
class Hit:
    repo: str
    path: str
    file_type: str
    label: str


def run_cmd(args: list[str], timeout: int) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
            text=True,
            errors="replace",
        )
        return proc.returncode, (proc.stdout or "").strip()
    except (subprocess.TimeoutExpired, OSError):
        return 1, ""


def ensure_7z() -> Path | None:
    """从 7z2600-linux-x64.tar.xz 准备 7zz，可重复执行。"""
    binary = SEVENZ_DIR / "7zz"
    if binary.exists() and os.access(binary, os.X_OK):
        return binary

    if not SEVENZ_ARCHIVE.exists():
        return None

    SEVENZ_DIR.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(SEVENZ_ARCHIVE, "r:xz") as tf:
            tf.extractall(SEVENZ_DIR)
    except (tarfile.TarError, OSError):
        return None

    # tar 内可能是顶层目录，兜底查找
    for candidate in SEVENZ_DIR.rglob("7zz"):
        try:
            mode = candidate.stat().st_mode
            candidate.chmod(mode | 0o111)
        except OSError:
            pass
        if os.access(candidate, os.X_OK):
            return candidate
    return None


def file_type_of(path: Path) -> str:
    if FILE_CMD_AVAILABLE:
        code, out = run_cmd(["file", "-b", str(path)], timeout=SCAN_TIMEOUT_SEC)
        if code == 0 and out:
            return out
    return fallback_file_type(path)


def fallback_file_type(path: Path) -> str:
    """Fallback when `file -b` is unavailable: minimal signature-based typing."""
    try:
        with path.open("rb") as f:
            head = f.read(4096)
    except OSError:
        return ""

    if head.startswith(b"\x7fELF"):
        return "ELF executable (fallback)"
    if head.startswith(b"MZ"):
        # Very lightweight PE32/PE32+ detection
        if len(head) >= 0x40:
            pe_off = int.from_bytes(head[0x3C:0x40], "little", signed=False)
            if pe_off + 0x1A8 <= len(head) and head[pe_off:pe_off + 4] == b"PE\x00\x00":
                machine_opt = pe_off + 24
                opt_magic = int.from_bytes(head[machine_opt:machine_opt + 2], "little", signed=False)
                characteristics = int.from_bytes(
                    head[pe_off + 22:pe_off + 24], "little", signed=False
                )
                is_dll = bool(characteristics & 0x2000)
                if opt_magic == 0x20B:
                    return "PE32+ executable (DLL) (fallback)" if is_dll else "PE32+ executable (fallback)"
                if opt_magic == 0x10B:
                    return "PE32 executable (DLL) (fallback)" if is_dll else "PE32 executable (fallback)"
        return "MZ executable (fallback)"
    if head.startswith(b"PK\x03\x04"):
        return "Zip archive data (fallback)"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7-zip archive data (fallback)"
    if head.startswith(b"Rar!\x1a\x07"):
        return "RAR archive data (fallback)"
    return ""


def strings_of(path: Path) -> str:
    code, out = run_cmd(["strings", "-a", str(path)], timeout=STRINGS_TIMEOUT_SEC)
    return out if code == 0 else ""


def is_native(file_type: str) -> bool:
    upper = file_type.upper()
    return any(marker.upper() in upper for marker in NATIVE_MARKERS)


def contains_any(haystack: str, needles: Iterable[str]) -> bool:
    h = haystack.lower()
    return any(n.lower() in h for n in needles)


def classify(sample_path: Path, file_type: str, strings_data: str) -> str | None:
    merged = f"{sample_path}\n{file_type}\n{strings_data}"
    if contains_any(merged, EXCLUDE_MARKERS):
        return None
    if contains_any(merged, CPP_MARKERS):
        return "high_confidence_cpp"
    return "likely_native_unknown"


def safe_extract_archive(archive: Path, sevenz_bin: Path, out_dir: Path) -> bool:
    password_file = archive.with_suffix(".pass")
    passwords: list[str | None] = [None]
    if password_file.exists():
        try:
            raw = password_file.read_text(encoding="utf-8", errors="ignore")
            values = [line.strip() for line in raw.splitlines() if line.strip()]
            # 常见样本密码文件有多行，逐个尝试
            if values:
                passwords.extend(values)
        except OSError:
            pass

    for pwd in passwords:
        cmd = [str(sevenz_bin), "x", "-y", f"-o{out_dir}"]
        if pwd is not None:
            cmd.append(f"-p{pwd}")
        cmd.append(str(archive))
        code, _ = run_cmd(cmd, timeout=60)
        if code == 0:
            return True
    return False


def iter_files(root: Path) -> Iterable[Path]:
    for dirpath, _, filenames in os.walk(root):
        for filename in filenames:
            yield Path(dirpath) / filename


def scan_repo(repo_dir: Path, sevenz_bin: Path | None) -> tuple[int, int, int, list[Hit]]:
    total_scanned = 0
    high = 0
    unknown = 0
    hits: list[Hit] = []

    with tempfile.TemporaryDirectory(prefix="scan_native_") as tmp:
        tmp_root = Path(tmp)
        queue = [repo_dir]
        seen_archives: set[Path] = set()

        while queue:
            current_root = queue.pop()
            for path in iter_files(current_root):
                if not path.is_file():
                    continue
                total_scanned += 1

                try:
                    if path.stat().st_size > MAX_FILE_SIZE:
                        continue
                except OSError:
                    continue

                ftype = file_type_of(path)
                if not ftype:
                    continue

                # 只解压已知压缩格式，且需要有 7z
                suffixes = {s.lower() for s in path.suffixes}
                if sevenz_bin and suffixes & KNOWN_ARCHIVE_SUFFIXES:
                    if path not in seen_archives:
                        seen_archives.add(path)
                        extracted = tmp_root / f"extract_{len(seen_archives)}"
                        extracted.mkdir(parents=True, exist_ok=True)
                        if safe_extract_archive(path, sevenz_bin, extracted):
                            queue.append(extracted)

                if not is_native(ftype):
                    continue

                sdata = strings_of(path)
                label = classify(path, ftype, sdata)
                if not label:
                    continue

                # 统一 repo/path 表达：repo 名 + 相对仓库路径
                if current_root != repo_dir:
                    rel_to_repo = Path("[extracted]") / path.relative_to(current_root)
                else:
                    rel_to_repo = path.relative_to(repo_dir)

                hits.append(
                    Hit(
                        repo=repo_dir.name,
                        path=str(rel_to_repo).replace("\\", "/"),
                        file_type=ftype,
                        label=label,
                    )
                )
                if label == "high_confidence_cpp":
                    high += 1
                else:
                    unknown += 1

    return total_scanned, high, unknown, hits


def write_outputs(hits: list[Hit]) -> None:
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)

    high_path = OUTPUTS_DIR / "high_confidence_cpp.txt"
    unk_path = OUTPUTS_DIR / "likely_native_unknown.txt"
    csv_path = OUTPUTS_DIR / "all_native_index.csv"

    highs = [f"{h.repo}/{h.path}" for h in hits if h.label == "high_confidence_cpp"]
    unks = [f"{h.repo}/{h.path}" for h in hits if h.label == "likely_native_unknown"]

    high_path.write_text("\n".join(highs) + ("\n" if highs else ""), encoding="utf-8")
    unk_path.write_text("\n".join(unks) + ("\n" if unks else ""), encoding="utf-8")

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["repo", "path", "file_type", "label"])
        for h in hits:
            w.writerow([h.repo, h.path, h.file_type, h.label])


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Index native C/C++ binaries from repositories.")
    parser.add_argument(
        "--repos-dir",
        default=str(REPOS_DIR),
        help="Directory containing cloned repos (default: ./repos).",
    )
    parser.add_argument(
        "--fallback-local-repo",
        action="store_true",
        help="If repos dir is empty, scan current repo root as a single repo.",
    )
    parser.add_argument(
        "--scan-path",
        default="",
        help="Optional explicit path to scan as a single repo (e.g. malware/Binaries).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    repos_dir = Path(args.repos_dir).resolve()
    repos_dir.mkdir(parents=True, exist_ok=True)

    for cmd in ("strings",):
        if shutil.which(cmd) is None:
            print(f"[error] required command not found in PATH: {cmd}")
            return 1
    if not FILE_CMD_AVAILABLE:
        print("[warn] `file` command not found; using fallback signature detector")

    sevenz_bin = ensure_7z()
    if sevenz_bin is None:
        print("[warn] 7zz unavailable, archive recursion will be skipped")

    repos = [p for p in repos_dir.iterdir() if p.is_dir()]
    all_hits: list[Hit] = []

    if args.scan_path:
        explicit = Path(args.scan_path).resolve()
        if not explicit.exists():
            print(f"[error] scan path not found: {explicit}")
            return 1
        scanned, high, unk, hits = scan_repo(explicit, sevenz_bin)
        for h in hits:
            h.repo = explicit.name
        all_hits.extend(hits)
        write_outputs(all_hits)
        print("\n=== Scan summary ===")
        print(f"repo={explicit.name} scanned_files={scanned} high_confidence_cpp={high} likely_native_unknown={unk}")
        print("\n=== Total ===")
        print(f"high_confidence_cpp={high}")
        print(f"likely_native_unknown={unk}")
        return 0

    if not repos:
        default_binaries = REPO_ROOT / "malware" / "Binaries"
        default_binares = REPO_ROOT / "malware" / "Binares"
        auto_target = default_binaries if default_binaries.exists() else default_binares
        if auto_target.exists():
            print(f"[info] repos/ is empty; auto-scan local directory: {auto_target}")
            scanned, high, unk, hits = scan_repo(auto_target, sevenz_bin)
            for h in hits:
                h.repo = auto_target.name
            all_hits.extend(hits)
            write_outputs(all_hits)
            print("\n=== Scan summary ===")
            print(f"repo={auto_target.name} scanned_files={scanned} high_confidence_cpp={high} likely_native_unknown={unk}")
            print("\n=== Total ===")
            print(f"high_confidence_cpp={high}")
            print(f"likely_native_unknown={unk}")
            return 0
        if args.fallback_local_repo:
            print("[info] repos/ is empty; fallback to scan current repository root")
            pseudo_repo_root = REPO_ROOT
            scanned, high, unk, hits = scan_repo(pseudo_repo_root, sevenz_bin)
            for h in hits:
                h.repo = pseudo_repo_root.name
            all_hits.extend(hits)
            write_outputs(all_hits)
            print("\n=== Scan summary ===")
            print(
                f"repo={pseudo_repo_root.name} scanned_files={scanned} "
                f"high_confidence_cpp={high} likely_native_unknown={unk}"
            )
            print("\n=== Total ===")
            print(f"high_confidence_cpp={high}")
            print(f"likely_native_unknown={unk}")
            return 0
        print("[info] repos/ is empty; nothing to scan")
        write_outputs(all_hits)
        return 0

    per_repo_stats: list[tuple[str, int, int, int]] = []

    for repo in sorted(repos):
        scanned, high, unk, hits = scan_repo(repo, sevenz_bin)
        all_hits.extend(hits)
        per_repo_stats.append((repo.name, scanned, high, unk))

    write_outputs(all_hits)

    print("\n=== Scan summary ===")
    for name, scanned, high, unk in per_repo_stats:
        print(f"repo={name} scanned_files={scanned} high_confidence_cpp={high} likely_native_unknown={unk}")

    print("\n=== Total ===")
    print(f"high_confidence_cpp={sum(x[2] for x in per_repo_stats)}")
    print(f"likely_native_unknown={sum(x[3] for x in per_repo_stats)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
