"""On-disk job store for repaired archives.

A job directory contains a finished ``<id>.tar`` plus its metadata **only
after** a repair has been built and verified.  In-progress work lives in a
private ``work/`` subdirectory and every failure removes its fragments, so
the download endpoint can only ever serve a complete archive.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import secrets
import threading
import time
from pathlib import Path


def _env_int(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, ""))
        return value if value > 0 else default
    except ValueError:
        return default


JOB_TTL_SECONDS = _env_int("PRIV_AUDIT_JOB_TTL", 3600)
MAX_JOBS = _env_int("PRIV_AUDIT_JOB_MAX", 20)


class JobError(Exception):
    def __init__(self, code: str, message: str, *, status_code: int = 404) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


@dataclass(frozen=True)
class JobRecord:
    job_id: str
    archive_name: str
    created_at: float
    report: dict
    archive_path: Path
    download_name: str

    def as_dict(self) -> dict:
        return {
            "job_id": self.job_id,
            "status": "complete",
            "archive_name": self.archive_name,
            "download_name": self.download_name,
            "created_at": self.created_at,
            "expires_at": self.created_at + JOB_TTL_SECONDS,
            "report": self.report,
            "download_url": f"/api/repair/jobs/{self.job_id}/download",
        }


class JobStore:
    def __init__(self, root: Path, *, ttl_seconds: int = JOB_TTL_SECONDS, max_jobs: int = MAX_JOBS) -> None:
        self._root = Path(root)
        self._work_root = self._root / "work"
        self._root.mkdir(parents=True, exist_ok=True)
        self._work_root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._ttl = ttl_seconds
        self._max_jobs = max_jobs

    def new_work_dir(self) -> tuple[str, Path]:
        job_id = secrets.token_urlsafe(16)
        work_dir = self._work_root / job_id
        work_dir.mkdir(parents=True, exist_ok=False)
        return job_id, work_dir

    def output_path_for(self, job_id: str) -> Path:
        return self._root / f"{job_id}.tar"

    def publish(self, job_id: str, *, archive_name: str, report: dict) -> JobRecord:
        archive_path = self.output_path_for(job_id)
        if not archive_path.is_file():
            raise JobError("job_not_ready", "修复归档尚未生成，无法开放下载", status_code=409)
        download_base = _safe_stem(archive_name)
        download_name = f"{download_base}-privilege-fixed-{job_id[:8]}.tar"
        record = JobRecord(
            job_id=job_id,
            archive_name=archive_name,
            created_at=time.time(),
            report=report,
            archive_path=archive_path,
            download_name=download_name,
        )
        meta_path = self._root / f"{job_id}.json"
        tmp_meta = self._root / f".{job_id}.json.tmp"
        tmp_meta.write_text(
            json.dumps(record.as_dict(), ensure_ascii=False), encoding="utf-8"
        )
        os.replace(tmp_meta, meta_path)
        self.cleanup()
        return record

    def get(self, job_id: str) -> JobRecord:
        if not job_id or not all(ch.isalnum() or ch in "-_" for ch in job_id):
            raise JobError("job_not_found", "修复任务不存在")
        meta_path = self._root / f"{job_id}.json"
        archive_path = self.output_path_for(job_id)
        if not meta_path.is_file() or not archive_path.is_file():
            raise JobError("job_not_found", "修复任务不存在或已过期清理")
        try:
            payload = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise JobError("job_corrupt", "修复任务元数据无法读取", status_code=500) from exc
        created_at = float(payload.get("created_at", time.time()))
        # The active store's TTL always wins; a stored expiry is advisory.
        if time.time() > created_at + self._ttl:
            self._discard(job_id)
            raise JobError("job_expired", "修复任务已过期，请重新发起修复")
        return JobRecord(
            job_id=job_id,
            archive_name=payload.get("archive_name", "image.tar"),
            created_at=created_at,
            report=payload.get("report", {}),
            archive_path=archive_path,
            download_name=payload.get(
                "download_name", f"privilege-fixed-{job_id[:8]}.tar"
            ),
        )

    def _discard(self, job_id: str) -> None:
        for path in (
            self._root / f"{job_id}.tar",
            self._root / f"{job_id}.json",
        ):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        work_dir = self._work_root / job_id
        if work_dir.exists():
            _rm_tree(work_dir)

    def cleanup(self) -> None:
        """Remove expired jobs and enforce the job cap. Best effort."""

        with self._lock:
            now = time.time()
            entries: list[tuple[float, str]] = []
            for meta_path in self._root.glob("*.json"):
                job_id = meta_path.name[: -len(".json")]
                try:
                    payload = json.loads(meta_path.read_text(encoding="utf-8"))
                    created = float(payload.get("created_at", now))
                except (OSError, ValueError, json.JSONDecodeError):
                    created = 0.0
                if created and now > created + self._ttl:
                    self._discard(job_id)
                    continue
                entries.append((created, job_id))

            entries.sort()
            while len(entries) > self._max_jobs:
                _, job_id = entries.pop(0)
                self._discard(job_id)

            # Orphaned work directories from crashed processes are removed too.
            for child in self._work_root.iterdir():
                if child.is_dir():
                    try:
                        age = now - child.stat().st_mtime
                    except OSError:
                        continue
                    if age > self._ttl:
                        _rm_tree(child)

    def discard_work(self, job_id: str) -> None:
        # _rm_tree removes the directory itself once it is empty.
        work_dir = self._work_root / job_id
        if work_dir.exists():
            _rm_tree(work_dir)


def _rm_tree(path: Path) -> None:
    for child in path.rglob("*"):
        if child.is_file() or child.is_symlink():
            child.unlink()
    for child in sorted(path.rglob("*"), reverse=True):
        if child.is_dir():
            child.rmdir()
    path.rmdir()


def _safe_stem(name: str) -> str:
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    cleaned = "".join(ch if (ch.isalnum() or ch in ".-_") else "_" for ch in base)
    cleaned = cleaned.strip("._-") or "image"
    if cleaned.endswith(".tar"):
        cleaned = cleaned[: -len(".tar")]
    return cleaned or "image"
