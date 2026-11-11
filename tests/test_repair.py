from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import tarfile
import tempfile
import unittest
from pathlib import Path

from app.merger import ScanError, scan_docker_archive
from app.repair import COPY_CHUNK, repair_archive
from app.sample import build_demo_archive

from tests.test_merger import make_archive, make_layer


def _tar_members(payload: bytes) -> dict[str, tarfile.TarInfo]:
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as tar:
        return {member.name: member for member in tar.getmembers()}


def _layer_payloads(archive: bytes) -> dict[str, bytes]:
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        manifest = json.loads(tar.extractfile("manifest.json").read().decode())
        out = {}
        for layer_path in manifest[0]["Layers"]:
            out[layer_path] = tar.extractfile(layer_path).read()
        out["__manifest__"] = json.dumps(manifest).encode()
        out["__config_path__"] = manifest[0]["Config"].encode()
        return out


def _inner_entries(archive: bytes, layer_path: str) -> dict[str, tarfile.TarInfo]:
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        data = tar.extractfile(layer_path).read()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as inner:
        return {member.name: member for member in inner.getmembers()}


def _config(archive: bytes) -> dict:
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        manifest = json.loads(tar.extractfile("manifest.json").read().decode())
        return json.loads(tar.extractfile(manifest[0]["Config"]).read().decode())


def _run(archive: bytes, paths: list[str]):
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        report = repair_archive(
            io.BytesIO(archive),
            paths,
            tmp_path / "fixed.tar",
            work_dir=tmp_path / "work",
        )
        data = report.output_path.read_bytes()
    return report, data


class RepairCoreTests(unittest.TestCase):
    def test_demo_full_repair_clears_all_flags_and_keeps_uid_gid_body(self):
        original = build_demo_archive()
        before = scan_docker_archive(io.BytesIO(original)).as_dict(source="t")
        self.assertEqual(before["summary"]["privileged_files"], 5)
        paths = [item["relative_path"] for item in before["files"]]

        report, fixed = _run(original, paths)
        self.assertEqual(len(report.selected), 5)

        after = scan_docker_archive(io.BytesIO(fixed)).as_dict(source="t")
        self.assertEqual(after["summary"]["privileged_files"], 0)
        self.assertEqual(len(after["layers"]), 5)

        before_by = {f["relative_path"]: f for f in before["files"]}
        after_entries = scan_docker_archive(io.BytesIO(fixed)).entries
        for selected in report.selected:
            entry = after_entries[selected.relative_path]
            self.assertEqual(entry.record.kind, "file")
            old = before_by[selected.relative_path]
            self.assertEqual(entry.record.uid, old["uid"])
            self.assertEqual(entry.record.gid, old["gid"])
            self.assertEqual(entry.record.mode, old["mode"] & ~0o6000)
            self.assertEqual(
                format(entry.record.mode, "04o"),
                format(selected.new_mode, "04o"),
            )
            # Sticky bit and ordinary rwx bits survive when present.

        # Config: diff_ids gains exactly one entry; history gains one entry;
        # runtime config/labels survive.
        cfg = _config(fixed)
        original_cfg = _config(original)
        self.assertEqual(
            len(cfg["rootfs"]["diff_ids"]),
            len(original_cfg["rootfs"]["diff_ids"]) + 1,
        )
        self.assertEqual(
            cfg["rootfs"]["diff_ids"][:-1], original_cfg["rootfs"]["diff_ids"]
        )
        self.assertEqual(
            len(cfg["history"]), len(original_cfg["history"]) + 1
        )
        self.assertEqual(cfg["config"], original_cfg["config"])
        self.assertEqual(cfg["rootfs"]["diff_ids"][-1], report.patch_diff_id)

        # Config blob filename is the digest of its content.
        with tarfile.open(fileobj=io.BytesIO(fixed), mode="r:") as tar:
            manifest = json.loads(
                tar.extractfile("manifest.json").read().decode()
            )
            config_bytes = tar.extractfile(manifest[0]["Config"]).read()
        config_path = manifest[0]["Config"]
        self.assertEqual(
            config_path, "blobs/sha256/" + hashlib.sha256(config_bytes).hexdigest()
        )
        self.assertEqual(
            manifest[0]["Layers"], report.layer_paths + [report.patch_layer_path]
        )

    def test_original_layer_bytes_are_identical(self):
        original = build_demo_archive()
        before = scan_docker_archive(io.BytesIO(original))
        report, fixed = _run(
            original, [before.files[0]["relative_path"]]
        )
        old_payloads = _layer_payloads(original)
        new_payloads = _layer_payloads(fixed)
        for layer_path in report.layer_paths:
            self.assertEqual(
                hashlib.sha256(new_payloads[layer_path]).hexdigest(),
                hashlib.sha256(old_payloads[layer_path]).hexdigest(),
                layer_path,
            )
        # The original four layers keep the same member names/paths.
        self.assertEqual(
            report.layer_paths,
            [layer["path"] for layer in before.as_dict(source="t")["layers"]],
        )

    def test_patch_layer_uses_original_body_uid_gid_and_only_clears_special_bits(self):
        original = build_demo_archive()
        before = scan_docker_archive(io.BytesIO(original))
        target = next(
            item for item in before.files if item["relative_path"] == "usr/bin/wall"
        )
        report, fixed = _run(original, ["usr/bin/wall"])
        inner = _inner_entries(fixed, report.patch_layer_path)
        self.assertEqual(set(inner), {"usr/bin/wall"})
        info = inner["usr/bin/wall"]
        self.assertEqual(info.mode & 0o6000, 0)
        self.assertEqual(info.mode & 0o7777, 0o755)  # 2755 -> 0755
        self.assertEqual(info.uid, target["uid"])
        self.assertEqual(info.gid, target["gid"])  # gid 5 retained

        # Body equals the last-effective version in the source layer.
        source_layer = target["layer_path"]
        with tarfile.open(fileobj=io.BytesIO(original), mode="r:") as tar:
            source_bytes = tar.extractfile(source_layer).read()
        with tarfile.open(fileobj=io.BytesIO(source_bytes), mode="r:") as layer:
            original_body = layer.extractfile("usr/bin/wall").read()
        with tarfile.open(fileobj=io.BytesIO(fixed), mode="r:") as tar:
            patch_bytes = tar.extractfile(report.patch_layer_path).read()
        with tarfile.open(fileobj=io.BytesIO(patch_bytes), mode="r:") as layer:
            repaired_body = layer.extractfile("usr/bin/wall").read()
        self.assertEqual(repaired_body, original_body)
        self.assertEqual(
            hashlib.sha256(original_body).hexdigest(),
            report.selected[0].body_digest,
        )

    def test_unselected_files_and_layers_remain_untouched(self):
        original = build_demo_archive()
        report, fixed = _run(original, ["usr/bin/ping"])
        after = scan_docker_archive(io.BytesIO(fixed)).as_dict(source="t")
        remaining = {item["relative_path"] for item in after["files"]}
        # Only ping was repaired; the other four findings stay flagged.
        self.assertNotIn("usr/bin/ping", remaining)
        self.assertEqual(len(remaining), 4)
        inner = _inner_entries(fixed, report.patch_layer_path)
        self.assertEqual(set(inner), {"usr/bin/ping"})

    def test_batch_rejected_when_any_path_is_not_privileged_regular(self):
        original = build_demo_archive()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            with self.assertRaises(ScanError) as caught:
                repair_archive(
                    io.BytesIO(original),
                    ["usr/bin/ping", "etc/motd"],
                    tmp_path / "fixed.tar",
                    work_dir=tmp_path / "work",
                )
            self.assertEqual(caught.exception.code, "selection_not_privileged_regular")
            self.assertEqual(caught.exception.path, "/etc/motd")
            # Nothing downloadable or even partially built remains.
            self.assertFalse((tmp_path / "fixed.tar").exists())
            self.assertEqual(list(Path(tmp).rglob("*.tar")), [])

    def test_batch_rejected_for_unknown_and_nonfile_paths(self):
        original = build_demo_archive()
        for bad_path in ["no/such/file", "usr/bin/ping-link"]:  # symlink case
            with self.assertRaises(ScanError) as caught:
                _run(original, ["usr/bin/ping", bad_path])
            self.assertEqual(caught.exception.code, "selection_not_privileged_regular")

    def test_empty_selection_rejected(self):
        original = build_demo_archive()
        with self.assertRaises(ScanError) as caught:
            _run(original, [])
        self.assertEqual(caught.exception.code, "selection_empty")

    def test_absolute_and_traversal_paths_are_normalized_or_rejected(self):
        original = build_demo_archive()
        # Leading slash is accepted as equivalent form.
        report, fixed = _run(original, ["/usr/bin/ping"])
        self.assertEqual(report.selected[0].relative_path, "usr/bin/ping")
        with self.assertRaises(ScanError) as caught:
            _run(original, ["../etc/passwd"])
        self.assertEqual(caught.exception.code, "unsafe_path")

    def test_gzip_layer_is_rejected_in_repair_mode(self):
        compressed_layer = gzip.compress(
            make_layer([{"name": "bin/tool", "mode": 0o4755, "data": b"x"}])
        )
        archive = make_archive([compressed_layer])
        with self.assertRaises(ScanError) as caught:
            _run(archive, ["bin/tool"])
        self.assertEqual(caught.exception.code, "compressed_unsupported")

    def test_gzip_outer_archive_is_rejected_in_repair_mode(self):
        layer = make_layer([{"name": "bin/tool", "mode": 0o4755, "data": b"x"}])
        archive = gzip.compress(make_archive([layer]))
        with self.assertRaises(ScanError) as caught:
            _run(archive, ["bin/tool"])
        self.assertEqual(caught.exception.code, "compressed_unsupported")

    def test_sticky_bit_and_rwx_are_preserved(self):
        layer = make_layer(
            [{"name": "tmp/tool", "mode": 0o6751, "uid": 1000, "gid": 1001, "data": b"abc"}]
        )
        archive = make_archive([layer])
        report, fixed = _run(archive, ["tmp/tool"])
        entries = scan_docker_archive(io.BytesIO(fixed)).entries
        mode = entries["tmp/tool"].record.mode
        self.assertEqual(mode, 0o0751)  # 6751: SUID/SGID removed, rwx intact
        self.assertEqual(entries["tmp/tool"].record.uid, 1000)
        self.assertEqual(entries["tmp/tool"].record.gid, 1001)

    def test_sticky_bit_survives_suid_removal(self):
        # 0o6751 has no sticky; use 0o7751 (SUID + sticky) to prove the
        # 0o1000 sticky bit is outside the SUID/SGID mask and is preserved.
        layer = make_layer(
            [{"name": "tmp/dir-tool", "mode": 0o7751, "uid": 7, "gid": 8, "data": b"d"}]
        )
        archive = make_archive([layer])
        _report, fixed = _run(archive, ["tmp/dir-tool"])
        with tarfile.open(fileobj=io.BytesIO(fixed), mode="r:") as tar:
            patch = tar.extractfile(_report.patch_layer_path).read()
        with tarfile.open(fileobj=io.BytesIO(patch), mode="r:") as inner:
            info = inner.getmember("tmp/dir-tool")
        self.assertEqual(info.mode & 0o7777, 0o1751)
        self.assertEqual((info.uid, info.gid), (7, 8))

    def test_repair_picks_last_effective_version_across_layers(self):
        base = make_layer(
            [{"name": "app/tool", "mode": 0o4755, "data": b"lower version"}]
        )
        upper = make_layer(
            [{"name": "app/tool", "mode": 0o4755, "data": b"upper version wins"}]
        )
        archive = make_archive([base, upper])
        report, fixed = _run(archive, ["app/tool"])
        with tarfile.open(fileobj=io.BytesIO(fixed), mode="r:") as tar:
            patch = tar.extractfile(report.patch_layer_path).read()
        with tarfile.open(fileobj=io.BytesIO(patch), mode="r:") as layer:
            self.assertEqual(layer.extractfile("app/tool").read(), b"upper version wins")
        # Lower layer bytes untouched.
        old = _layer_payloads(archive)
        new = _layer_payloads(fixed)
        for path in report.layer_paths:
            self.assertEqual(old[path], new[path])

    def test_large_file_is_copied_in_chunks_not_single_read(self):
        body = os.urandom(COPY_CHUNK * 2 + 12345)

        class CountingStream:
            def __init__(self, data):
                self._buf = io.BytesIO(data)
                self.read_sizes = []

            def read(self, size=-1):
                self.read_sizes.append(size)
                return self._buf.read(size)

        layer_buffer = io.BytesIO()
        with tarfile.open(fileobj=layer_buffer, mode="w", format=tarfile.PAX_FORMAT) as tar:
            info = tarfile.TarInfo("big/bin")
            info.mode = 0o4755
            info.size = len(body)
            tar.addfile(info, io.BytesIO(body))
        archive = make_archive([layer_buffer.getvalue()])

        # Patch builder streams through _HashingReader whose reads are capped.
        report, fixed = _run(archive, ["big/bin"])
        with tarfile.open(fileobj=io.BytesIO(fixed), mode="r:") as tar:
            patch = tar.extractfile(report.patch_layer_path).read()
        with tarfile.open(fileobj=io.BytesIO(patch), mode="r:") as layer:
            self.assertEqual(layer.extractfile("big/bin").read(), body)

        # Directly prove the chunk cap: a 2.5 MiB stream requires >=3 reads.
        counter = CountingStream(body)
        from app.repair import _HashingReader

        reader = _HashingReader(counter, len(body))
        collected = b""
        while True:
            chunk = reader.read(COPY_CHUNK)
            if not chunk:
                break
            collected += chunk
        self.assertEqual(collected, body)
        self.assertGreaterEqual(len(counter.read_sizes), 3)
        self.assertTrue(all(size <= COPY_CHUNK for size in counter.read_sizes))

    def test_repaired_archive_is_uncompressed_and_loadable_structure(self):
        original = build_demo_archive()
        before = scan_docker_archive(io.BytesIO(original))
        _report, fixed = _run(
            original, [item["relative_path"] for item in before.files]
        )
        # Plain tar magic, not gzip/xz.
        self.assertNotIn(fixed[:2], (b"\x1f\x8b", b"BZ"))
        with tarfile.open(fileobj=io.BytesIO(fixed), mode="r:") as tar:
            names = tar.getnames()
        self.assertIn("manifest.json", names)
        self.assertTrue(any(name.startswith("blobs/sha256/") for name in names))

    def test_runtime_config_and_labels_are_preserved(self):
        layer = make_layer([{"name": "bin/tool", "mode": 0o4755, "data": b"x"}])
        archive = make_archive([layer])
        original_cfg = _config(archive)
        _report, fixed = _run(archive, ["bin/tool"])
        new_cfg = _config(fixed)
        self.assertEqual(new_cfg["config"], original_cfg["config"])
        self.assertEqual(new_cfg["config"]["Labels"], {"test.label": "preserve-me"})
        self.assertEqual(new_cfg["architecture"], "amd64")
        self.assertEqual(new_cfg["os"], "linux")
        # RepoTags survive in the manifest.
        with tarfile.open(fileobj=io.BytesIO(fixed), mode="r:") as tar:
            manifest = json.loads(tar.extractfile("manifest.json").read())
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
            old_manifest = json.loads(tar.extractfile("manifest.json").read())
        self.assertEqual(manifest[0]["RepoTags"], old_manifest[0]["RepoTags"])


class RepairApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import shutil

        from fastapi.testclient import TestClient

        from app import main as main_module

        cls._shutil = shutil
        cls._tmpdir = tempfile.mkdtemp(prefix="repair-jobs-test-")
        main_module.job_store = main_module.JobStore(Path(cls._tmpdir))
        cls.client = TestClient(main_module.app)
        cls.job_store = main_module.job_store

    @classmethod
    def tearDownClass(cls):
        cls._shutil.rmtree(cls._tmpdir, ignore_errors=True)

    def setUp(self):
        # Each API test starts with an empty, isolated job store.
        for child in Path(self._tmpdir).iterdir():
            if child.is_dir():
                self._shutil.rmtree(child, ignore_errors=True)
            else:
                child.unlink()

    def test_full_upload_repair_and_download_flow(self):
        archive = build_demo_archive()
        scan = self.client.post(
            "/api/scan", files={"archive": ("demo.tar", archive, "application/x-tar")}
        )
        self.assertEqual(scan.status_code, 200)
        paths = [item["relative_path"] for item in scan.json()["files"]]

        response = self.client.post(
            "/api/repair",
            files={"archive": ("demo.tar", archive, "application/x-tar")},
            data={"paths_json": json.dumps(paths)},
        )
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(payload["status"], "complete")
        job = payload["job"]
        self.assertEqual(job["report"]["selected_count"], 5)

        downloaded = self.client.get(job["download_url"])
        self.assertEqual(downloaded.status_code, 200)
        self.assertEqual(
            downloaded.headers["content-type"], "application/x-tar"
        )
        self.assertIn("attachment;", downloaded.headers["content-disposition"])
        self.assertIn("demo-privilege-fixed-", downloaded.headers["content-disposition"])
        # Served bytes pass a fresh strict scan with zero findings.
        re_scan = scan_docker_archive(io.BytesIO(downloaded.content))
        self.assertEqual(re_scan.files, [])

        status = self.client.get(f"/api/repair/jobs/{job['job_id']}")
        self.assertEqual(status.status_code, 200)
        self.assertEqual(status.json()["status"], "complete")

        verify = self.client.post(f"/api/repair/jobs/{job['job_id']}/scan")
        self.assertEqual(verify.status_code, 200)
        self.assertEqual(verify.json()["summary"]["privileged_files"], 0)

    def test_repair_rejects_batch_without_leaving_fragments(self):
        archive = build_demo_archive()
        response = self.client.post(
            "/api/repair",
            files={"archive": ("demo.tar", archive, "application/x-tar")},
            data={"paths_json": json.dumps(["etc/motd"])},
        )
        self.assertEqual(response.status_code, 400)
        detail = response.json()["detail"]
        self.assertEqual(detail["code"], "selection_not_privileged_regular")
        self.assertEqual(detail["path"], "/etc/motd")

        # No job artifacts (tar/json) exist outside work directories.
        root = self.job_store._root
        self.assertEqual(list(root.glob("*.tar")), [])
        self.assertEqual(list(root.glob("*.json")), [])
        self.assertEqual(list((root / "work").iterdir()), [])

    def test_demo_repair_endpoint(self):
        response = self.client.post(
            "/api/demo/repair",
            data={"paths_json": json.dumps(["usr/bin/ping", "usr/bin/wall"])},
        )
        self.assertEqual(response.status_code, 200, response.text)
        job = response.json()["job"]
        downloaded = self.client.get(job["download_url"])
        self.assertEqual(downloaded.status_code, 200)
        result = scan_docker_archive(io.BytesIO(downloaded.content)).as_dict(source="t")
        remaining = {f["relative_path"] for f in result["files"]}
        self.assertNotIn("usr/bin/ping", remaining)
        self.assertNotIn("usr/bin/wall", remaining)
        self.assertEqual(len(remaining), 3)

    def test_compressed_upload_is_rejected_over_http(self):
        layer = make_layer([{"name": "a", "mode": 0o4755}])
        archive = gzip.compress(make_archive([layer]))
        response = self.client.post(
            "/api/repair",
            files={"archive": ("x.tar.gz", archive, "application/gzip")},
            data={"paths_json": json.dumps(["a"])},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"]["code"], "compressed_unsupported")

    def test_missing_archive_and_empty_selection(self):
        response = self.client.post(
            "/api/repair", data={"paths_json": json.dumps(["a"])}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"]["code"], "file_missing")

        archive = build_demo_archive()
        response = self.client.post(
            "/api/repair",
            files={"archive": ("demo.tar", archive, "application/x-tar")},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"]["code"], "selection_empty")

    def test_unknown_job_id_is_404(self):
        response = self.client.get("/api/repair/jobs/does-not-exist/download")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["detail"]["code"], "job_not_found")


class JobStoreTests(unittest.TestCase):
    def _store(self, tmp: str, **kwargs):
        from app.jobs import JobStore

        return JobStore(Path(tmp), **kwargs)

    def test_publish_get_download_and_expiry(self):
        import time

        with tempfile.TemporaryDirectory() as tmp:
            store = self._store(tmp, ttl_seconds=60)
            job_id, work_dir = store.new_work_dir()
            output = store.output_path_for(job_id)
            output.write_bytes(b"tar-bytes")
            (work_dir / "scratch").write_text("x")
            record = store.publish(
                job_id, archive_name="img.tar", report={"selected_count": 1}
            )
            self.assertTrue(record.archive_path.is_file())
            fetched = store.get(job_id)
            self.assertEqual(fetched.download_name, record.download_name)
            self.assertTrue(fetched.download_name.endswith(".tar"))
            # The route layer discards the private work directory on success.
            store.discard_work(job_id)
            self.assertFalse(work_dir.exists())

            # Expired jobs are reported and removed on access.
            expired = self._store(tmp, ttl_seconds=1)
            time.sleep(1.1)
            with self.assertRaises(Exception) as caught:
                expired.get(job_id)
            self.assertEqual(caught.exception.code, "job_expired")
            self.assertFalse(output.exists())

    def test_job_cap_evicts_oldest(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = self._store(tmp, ttl_seconds=3600, max_jobs=2)
            ids = []
            for index in range(3):
                job_id, work_dir = store.new_work_dir()
                store.output_path_for(job_id).write_bytes(f"b{index}".encode())
                store.publish(job_id, archive_name=f"i{index}.tar", report={})
                ids.append(job_id)
            # Oldest job is evicted; the two newest remain.
            self.assertFalse(store.output_path_for(ids[0]).exists())
            self.assertTrue(store.output_path_for(ids[1]).exists())
            self.assertTrue(store.output_path_for(ids[2]).exists())

    def test_discard_work_removes_fragment_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = self._store(tmp)
            job_id, work_dir = store.new_work_dir()
            (work_dir / "nested").mkdir()
            (work_dir / "nested" / "fragment.tar").write_bytes(b"x")
            store.discard_work(job_id)
            self.assertFalse(work_dir.exists())
            self.assertFalse(any(Path(tmp).rglob("*.tar")))


if __name__ == "__main__":
    unittest.main()
