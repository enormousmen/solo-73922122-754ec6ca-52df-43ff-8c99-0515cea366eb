"""Privilege-downgrade repair for single-image docker-save archives.

The repair flow never executes an image or unpacked file.  It re-parses the
uploaded archive with the same read-only merger used by the scanner, appends
one extra uncompressed layer containing corrected copies of the selected
files, rewrites the image config/manifest, and publishes the result only after
a full verification pass.

Hard guarantees:

* every selected path must still be a final, privileged regular file after
  whiteout merging, otherwise the whole batch is rejected before any output
  byte is written;
* original layer members are copied byte for byte (verified by sha256 after
  the output archive is written);
* only SUID/SGID bits are cleared -- file bodies, UID/GID and the remaining
  permission bits are preserved;
* file bodies are always copied through fixed-size chunks, so memory use does
  not grow with image size;
* the repaired archive appears at its download path via an atomic rename only,
  and every failure removes the temporary fragment.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile

from app.merger import (
    SPECIAL_BITS,
    ScanError,
    _map_outer_members,
    normalize_archive_path,
    scan_docker_archive,
)

COPY_CHUNK = 1024 * 1024  # 1 MiB: every file body moves in chunks this size
TAR_FORMAT = tarfile.PAX_FORMAT


class _ChunkCapReader:
    """Wrap a stream so a single ``read`` never returns more than one chunk."""

    def __init__(self, stream, limit: int) -> None:
        self._stream = stream
        self._remaining = limit

    def read(self, size: int = -1) -> bytes:
        if self._remaining <= 0:
            return b""
        if size is None or size < 0 or size > COPY_CHUNK:
            size = COPY_CHUNK
        chunk = self._stream.read(min(size, self._remaining))
        self._remaining -= len(chunk)
        return chunk


class _HashingReader:
    """Chunked reader that hashes exactly the bytes handed to the tar writer."""

    def __init__(self, stream, limit: int) -> None:
        self._cap = _ChunkCapReader(stream, limit)
        self.digest = hashlib.sha256()
        self.bytes_read = 0

    def read(self, size: int = -1) -> bytes:
        chunk = self._cap.read(size)
        self.digest.update(chunk)
        self.bytes_read += len(chunk)
        return chunk


def _hash_stream(stream, limit: int) -> str:
    digest = hashlib.sha256()
    remaining = limit
    while remaining > 0:
        chunk = stream.read(min(COPY_CHUNK, remaining))
        if not chunk:
            raise ScanError("layer_invalid", "图层数据意外结束")
        digest.update(chunk)
        remaining -= len(chunk)
    return digest.hexdigest()


def _new_tar_writer(fileobj) -> tarfile.TarFile:
    tar = tarfile.open(fileobj=fileobj, mode="w", format=TAR_FORMAT)
    # Keep the library's internal copies chunked as well.
    tar.copybufsize = COPY_CHUNK
    return tar


@dataclass
class SelectedFile:
    relative_path: str
    layer_path: str
    old_mode: int
    new_mode: int
    uid: int
    gid: int
    size: int
    body_digest: str

    def as_dict(self) -> dict:
        return {
            "path": "/" + self.relative_path,
            "relative_path": self.relative_path,
            "layer_path": self.layer_path,
            "old_mode": self.old_mode & 0o7777,
            "old_mode_octal": format(self.old_mode & 0o7777, "04o"),
            "new_mode": self.new_mode & 0o7777,
            "new_mode_octal": format(self.new_mode & 0o7777, "04o"),
            "uid": self.uid,
            "gid": self.gid,
            "size": self.size,
            "body_digest": "sha256:" + self.body_digest,
        }


@dataclass
class RepairReport:
    selected: list[SelectedFile]
    layer_paths: list[str]
    patch_layer_path: str
    patch_diff_id: str
    old_config_path: str | None
    new_config_path: str
    output_path: Path
    output_size: int
    original_digests: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "selected_files": [item.as_dict() for item in self.selected],
            "selected_count": len(self.selected),
            "layers": list(self.layer_paths),
            "layer_count": len(self.layer_paths),
            "patch_layer": {
                "path": self.patch_layer_path,
                "diff_id": self.patch_diff_id,
            },
            "config": {
                "old_path": self.old_config_path,
                "new_path": self.new_config_path,
            },
            "output_size": self.output_size,
        }


def _normalize_selection(raw_paths: list[str]) -> list[str]:
    if not raw_paths:
        raise ScanError("selection_empty", "未选择任何需要修复的文件路径")

    ordered: list[str] = []
    seen: set[str] = set()
    for raw in raw_paths:
        if not isinstance(raw, str):
            raise ScanError("selection_invalid", "修复路径必须是字符串")
        candidate = raw.lstrip("/")
        try:
            path = normalize_archive_path(candidate, context="修复选择")
        except ScanError as exc:
            raise ScanError(exc.code, exc.message, path=raw) from exc
        if not path:
            raise ScanError("selection_invalid", "修复路径不能为空", path=raw)
        if path not in seen:
            seen.add(path)
            ordered.append(path)
    return ordered


def _validate_selection(paths: list[str], entries: dict):
    """Reject the whole batch unless every path is a final privileged file."""

    by_layer: dict[str, list[str]] = {}
    details: dict[str, object] = {}

    for relative_path in paths:
        entry = entries.get(relative_path)
        if entry is None:
            raise ScanError(
                "selection_not_privileged_regular",
                "所选路径在最终合并视图中不存在；整批修复已拒绝",
                path="/" + relative_path,
            )
        record = entry.record
        if record.kind != "file":
            raise ScanError(
                "selection_not_privileged_regular",
                f"所选路径不是普通文件（当前类型：{record.kind}）；整批修复已拒绝",
                path="/" + relative_path,
                layer_number=entry.layer.number,
                layer_path=entry.layer.path,
            )
        if not (record.mode & SPECIAL_BITS):
            raise ScanError(
                "selection_not_privileged_regular",
                "所选路径不是最终仍带 SUID/SGID 位的高权限普通文件；整批修复已拒绝",
                path="/" + relative_path,
                layer_number=entry.layer.number,
                layer_path=entry.layer.path,
            )
        by_layer.setdefault(entry.layer.path, []).append(relative_path)
        details[relative_path] = entry

    return {"by_layer": by_layer, "entries": details}


def _add_directory(tar: tarfile.TarFile, name: str) -> None:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE
    info.mode = 0o755
    info.uid = 0
    info.gid = 0
    info.mtime = 0
    tar.addfile(info)


def _build_patch_layer(
    outer: tarfile.TarFile,
    members: dict[str, tarfile.TarInfo],
    by_layer: dict[str, list[str]],
    details: dict[str, object],
    patch_file,
) -> list[SelectedFile]:
    """Stream the selected bodies into one new uncompressed layer tar.

    Only the *final* regular-file header of each selected path is copied, so
    duplicate headers inside a source layer collapse into one corrected entry.
    """

    selected: dict[str, SelectedFile] = {}

    with _new_tar_writer(patch_file) as patch_tar:
        for layer_path, relative_paths in by_layer.items():
            layer_member = members[layer_path]
            extracted = outer.extractfile(layer_member)
            if extracted is None:
                raise ScanError(
                    "layer_unreadable",
                    f"无法读取镜像层 {layer_path}",
                    layer_path=layer_path,
                )
            wanted = set(relative_paths)
            try:
                # Random access lets a later duplicate header supersede an
                # earlier one without buffering whole file bodies in memory.
                with tarfile.open(fileobj=extracted, mode="r:") as layer_tar:
                    last_index: dict[str, int] = {}
                    ordered_names: list[str] = []
                    for index, member_info in enumerate(layer_tar.getmembers()):
                        normalized = normalize_archive_path(
                            member_info.name, context=f"镜像层 {layer_path}"
                        )
                        if normalized in wanted and member_info.isreg():
                            if normalized not in last_index:
                                ordered_names.append(normalized)
                            last_index[normalized] = index

                    missing = wanted - set(last_index)
                    if missing:
                        raise ScanError(
                            "selection_not_privileged_regular",
                            "所选文件未能在其最后写入层中定位到普通文件正文；整批修复已拒绝",
                            path="/" + sorted(missing)[0],
                            layer_path=layer_path,
                        )

                    for normalized in ordered_names:
                        member_info = layer_tar.getmembers()[last_index[normalized]]
                        source = layer_tar.extractfile(member_info)
                        if source is None:
                            raise ScanError(
                                "layer_unreadable",
                                f"无法读取图层成员 {member_info.name}",
                                layer_path=layer_path,
                            )
                        info = tarfile.TarInfo(normalized)
                        info.type = tarfile.REGTYPE
                        info.size = member_info.size
                        info.mode = (member_info.mode & ~SPECIAL_BITS) & 0o7777
                        info.uid = member_info.uid
                        info.gid = member_info.gid
                        info.mtime = member_info.mtime
                        reader = _HashingReader(source, member_info.size)
                        patch_tar.addfile(info, reader)
                        if reader.bytes_read != member_info.size:
                            raise ScanError(
                                "layer_invalid",
                                f"图层成员 {normalized} 正文长度与头部不一致",
                                layer_path=layer_path,
                            )
                        entry = details[normalized]
                        selected[normalized] = SelectedFile(
                            relative_path=normalized,
                            layer_path=layer_path,
                            old_mode=entry.record.mode,
                            new_mode=info.mode,
                            uid=info.uid,
                            gid=info.gid,
                            size=member_info.size,
                            body_digest=reader.digest.hexdigest(),
                        )
            finally:
                extracted.close()

    return [selected[key] for key in sorted(selected)]


def _load_image_config(
    outer: tarfile.TarFile,
    members: dict[str, tarfile.TarInfo],
    config_path: str | None,
):
    if not config_path or config_path not in members:
        raise ScanError(
            "config_missing",
            "manifest.json 引用的 config 不存在；无法同步镜像配置",
            path=config_path,
        )
    member = members[config_path]
    if not member.isfile():
        raise ScanError(
            "config_invalid",
            "config 不是普通文件；拒绝跟随符号链接或特殊文件",
            path=config_path,
        )
    extracted = outer.extractfile(member)
    if extracted is None:
        raise ScanError("config_invalid", "无法读取 config", path=config_path)
    try:
        payload = extracted.read()
    finally:
        extracted.close()
    try:
        config = json.loads(payload.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ScanError(
            "config_invalid",
            f"config 不是有效的 UTF-8 JSON：{exc}",
            path=config_path,
        ) from exc
    if not isinstance(config, dict):
        raise ScanError(
            "config_invalid", "config 顶层必须是 JSON 对象", path=config_path
        )
    return config, config_path


def _update_config(config: dict, patch_diff_id: str) -> bytes:
    rootfs = config.get("rootfs")
    if not isinstance(rootfs, dict) or not isinstance(rootfs.get("diff_ids"), list):
        raise ScanError(
            "config_invalid",
            "config.rootfs.diff_ids 缺失或格式错误；无法追加补丁层摘要",
        )
    diff_ids = list(rootfs["diff_ids"])
    if any(not isinstance(item, str) for item in diff_ids):
        raise ScanError("config_invalid", "config.rootfs.diff_ids 中存在非字符串项")
    diff_ids.append(patch_diff_id)
    config["rootfs"] = {**rootfs, "diff_ids": diff_ids}

    history_entry = {
        "created": "1970-01-01T00:00:00Z",
        "created_by": "privilege-audit: clear SUID/SGID bits on selected regular files",
        "comment": "append-only repair layer; original layer bytes are unchanged",
        "empty_layer": False,
    }
    history = config.get("history")
    config["history"] = (list(history) + [history_entry]) if isinstance(history, list) else [history_entry]

    # Runtime config and labels live elsewhere in the object and are untouched.
    return json.dumps(
        config, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _write_blob(tar: tarfile.TarFile, path: str, source, size: int, *, mtime: int) -> None:
    info = tarfile.TarInfo(path)
    info.type = tarfile.REGTYPE
    info.mode = 0o644
    info.uid = 0
    info.gid = 0
    info.mtime = mtime
    info.size = size
    tar.addfile(info, source)


def _verify_patch_bodies(
    outer: tarfile.TarFile,
    members: dict[str, tarfile.TarInfo],
    patch_layer_path: str,
    selected: list[SelectedFile],
) -> None:
    member = members[patch_layer_path]
    extracted = outer.extractfile(member)
    if extracted is None:
        raise ScanError("repair_verify_failed", "无法回读补丁层", path=patch_layer_path)
    try:
        with tarfile.open(fileobj=extracted, mode="r|") as patch_tar:
            bodies: dict[str, tuple[int, int, int, str]] = {}
            for info in patch_tar:
                if not info.isreg():
                    raise ScanError(
                        "repair_verify_failed",
                        "补丁层包含非普通文件成员",
                        path=info.name,
                    )
                source = patch_tar.extractfile(info)
                if source is None:
                    raise ScanError("repair_verify_failed", "无法读取补丁层成员")
                digest = _hash_stream(source, info.size)
                normalized = normalize_archive_path(info.name, context="补丁层")
                bodies[normalized] = (info.mode, info.uid, info.gid, digest)
    finally:
        extracted.close()

    if set(bodies) != {item.relative_path for item in selected}:
        raise ScanError("repair_verify_failed", "补丁层成员与修复选择不一致")
    for item in selected:
        mode, uid, gid, digest = bodies[item.relative_path]
        if digest != item.body_digest:
            raise ScanError(
                "repair_verify_failed",
                "补丁层正文与原文件最后有效版本不一致",
                path="/" + item.relative_path,
            )
        if (mode, uid, gid) != (item.new_mode, item.uid, item.gid):
            raise ScanError(
                "repair_verify_failed",
                "补丁层权限或 UID/GID 不符合预期",
                path="/" + item.relative_path,
            )


def _verify_output(
    output_path: Path,
    *,
    layer_paths: list[str],
    original_digests: dict[str, str],
    patch_layer_path: str,
    patch_digest: str,
    new_config_path: str,
    selected: list[SelectedFile],
) -> None:
    with output_path.open("rb") as handle:
        # Strict re-scan: outer tar and every layer must stay uncompressed.
        result = scan_docker_archive(handle, uncompressed_only=True)

        handle.seek(0)
        with tarfile.open(fileobj=handle, mode="r:") as outer:
            members = _map_outer_members(outer)

            for layer_path in layer_paths:
                member = members.get(layer_path)
                if member is None or not member.isfile():
                    raise ScanError(
                        "repair_verify_failed",
                        f"修复归档缺少原图层成员：{layer_path}",
                    )
                extracted = outer.extractfile(member)
                if extracted is None:
                    raise ScanError(
                        "repair_verify_failed", "无法回读修复归档图层", layer_path=layer_path
                    )
                try:
                    actual = _hash_stream(extracted, member.size)
                finally:
                    extracted.close()
                if actual != original_digests[layer_path]:
                    raise ScanError(
                        "repair_verify_failed",
                        f"原图层字节校验失败：{layer_path}",
                        layer_path=layer_path,
                    )

            patch_member = members.get(patch_layer_path)
            if patch_member is None or not patch_member.isfile():
                raise ScanError(
                    "repair_verify_failed", "修复归档缺少补丁层成员", path=patch_layer_path
                )
            extracted = outer.extractfile(patch_member)
            if extracted is None:
                raise ScanError("repair_verify_failed", "无法回读补丁层")
            try:
                if _hash_stream(extracted, patch_member.size) != patch_digest:
                    raise ScanError(
                        "repair_verify_failed", "补丁层字节校验失败", path=patch_layer_path
                    )
            finally:
                extracted.close()

            _verify_patch_bodies(outer, members, patch_layer_path, selected)

            config_member = members.get(new_config_path)
            if config_member is None or not config_member.isfile():
                raise ScanError(
                    "repair_verify_failed", "修复归档缺少新 config", path=new_config_path
                )
            extracted = outer.extractfile(config_member)
            if extracted is None:
                raise ScanError("repair_verify_failed", "无法回读新 config")
            try:
                config_bytes = extracted.read()
            finally:
                extracted.close()
            if hashlib.sha256(config_bytes).hexdigest() != new_config_path.rsplit("/", 1)[-1]:
                raise ScanError(
                    "repair_verify_failed", "config 摘要文件名与内容不一致", path=new_config_path
                )
            config = json.loads(config_bytes.decode("utf-8"))
            diff_ids = config["rootfs"]["diff_ids"]
            if diff_ids[-1] != "sha256:" + patch_digest:
                raise ScanError("repair_verify_failed", "rootfs.diff_ids 未包含补丁层摘要")
            if len(diff_ids) != len(layer_paths) + 1:
                raise ScanError("repair_verify_failed", "rootfs.diff_ids 数量不正确")
            if len(config.get("history", [])) < 1:
                raise ScanError("repair_verify_failed", "config.history 未追加修复记录")

            manifest_member = members.get("manifest.json")
            if manifest_member is None:
                raise ScanError("repair_verify_failed", "修复归档缺少 manifest.json")
            extracted = outer.extractfile(manifest_member)
            if extracted is None:
                raise ScanError("repair_verify_failed", "无法回读 manifest.json")
            try:
                manifest = json.loads(extracted.read().decode("utf-8"))
            finally:
                extracted.close()
            expected_layers = list(layer_paths) + [patch_layer_path]
            if manifest[0]["Layers"] != expected_layers:
                raise ScanError("repair_verify_failed", "manifest.json 的 Layers 引用不正确")
            if manifest[0]["Config"] != new_config_path:
                raise ScanError("repair_verify_failed", "manifest.json 的 Config 引用不正确")

        remaining = {item["relative_path"] for item in result.files}
        for item in selected:
            if item.relative_path in remaining:
                raise ScanError(
                    "repair_verify_failed",
                    "修复后所选路径仍带 SUID/SGID 位",
                    path="/" + item.relative_path,
                )
            entry = result.entries.get(item.relative_path)
            if entry is None or entry.record.kind != "file":
                raise ScanError(
                    "repair_verify_failed",
                    "修复后所选路径不再是普通文件",
                    path="/" + item.relative_path,
                )
            if entry.record.mode != item.new_mode:
                raise ScanError(
                    "repair_verify_failed",
                    f"修复后权限位不符合预期：{format(entry.record.mode, '04o')}",
                    path="/" + item.relative_path,
                )
            if (entry.record.uid, entry.record.gid) != (item.uid, item.gid):
                raise ScanError(
                    "repair_verify_failed",
                    "修复后 UID/GID 发生变化",
                    path="/" + item.relative_path,
                )


def _read_manifest(outer: tarfile.TarFile, members: dict[str, tarfile.TarInfo]) -> dict:
    member = members["manifest.json"]
    extracted = outer.extractfile(member)
    if extracted is None:
        raise ScanError("manifest_invalid", "无法读取 manifest.json")
    try:
        manifest = json.loads(extracted.read().decode("utf-8-sig"))
    finally:
        extracted.close()
    if not isinstance(manifest, list) or not isinstance(manifest[0], dict):
        raise ScanError("manifest_invalid", "manifest.json 结构无效")
    return dict(manifest[0])


def repair_archive(
    fileobj,
    raw_paths: list[str],
    output_path: Path,
    *,
    work_dir: Path,
) -> RepairReport:
    """Build the repaired archive and publish it atomically at ``output_path``."""

    output_path = Path(output_path)
    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)

    # Phase 1: re-merge the uploaded archive under the strict contract.
    scan = scan_docker_archive(fileobj, uncompressed_only=True)
    paths = _normalize_selection(raw_paths)
    selection = _validate_selection(paths, scan.entries)
    by_layer = selection["by_layer"]
    details = selection["entries"]
    layer_paths = [layer.path for layer in scan.layers]
    old_config_path = scan.image.get("config_path")

    patch_tmp = work_dir / "patch-layer.tar"
    output_tmp = work_dir / f".{output_path.name}.tmp-{os.urandom(6).hex()}"

    try:
        # Phase 2: build the append-only patch layer from the original bodies.
        fileobj.seek(0)
        with tarfile.open(fileobj=fileobj, mode="r:") as outer:
            members = _map_outer_members(outer)
            with patch_tmp.open("wb") as patch_handle:
                selected = _build_patch_layer(
                    outer, members, by_layer, details, patch_handle
                )
        patch_bytes = patch_tmp.read_bytes()
        patch_digest = hashlib.sha256(patch_bytes).hexdigest()
        patch_diff_id = "sha256:" + patch_digest
        patch_layer_path = f"blobs/sha256/{patch_digest}"

        # Phase 3: refresh config (diff_ids/history) and manifest.
        fileobj.seek(0)
        with tarfile.open(fileobj=fileobj, mode="r:") as outer:
            members = _map_outer_members(outer)
            config, old_config_path = _load_image_config(
                outer, members, old_config_path
            )
            config_bytes = _update_config(config, patch_diff_id)
            config_digest = hashlib.sha256(config_bytes).hexdigest()
            new_config_path = f"blobs/sha256/{config_digest}"

            manifest_entry = _read_manifest(outer, members)
            manifest = [
                {
                    **manifest_entry,
                    "Config": new_config_path,
                    "Layers": list(layer_paths) + [patch_layer_path],
                }
            ]
            manifest_bytes = json.dumps(
                manifest, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")

            # Phase 4: write a brand-new outer tar.  Original layer members
            # stream through unchanged and are hashed while they move.
            original_digests: dict[str, str] = {}
            with output_tmp.open("wb") as output_handle:
                with _new_tar_writer(output_handle) as out_tar:
                    _add_directory(out_tar, "blobs")
                    _add_directory(out_tar, "blobs/sha256")
                    _write_blob(
                        out_tar,
                        "manifest.json",
                        io.BytesIO(manifest_bytes),
                        len(manifest_bytes),
                        mtime=0,
                    )
                    _write_blob(
                        out_tar,
                        new_config_path,
                        io.BytesIO(config_bytes),
                        len(config_bytes),
                        mtime=0,
                    )

                    for layer_path in layer_paths:
                        member = members[layer_path]
                        extracted = outer.extractfile(member)
                        if extracted is None:
                            raise ScanError(
                                "layer_unreadable",
                                f"无法读取镜像层 {layer_path}",
                                layer_path=layer_path,
                            )
                        try:
                            info = tarfile.TarInfo(layer_path)
                            info.type = tarfile.REGTYPE
                            info.mode = member.mode & 0o7777
                            info.uid = member.uid
                            info.gid = member.gid
                            info.mtime = member.mtime
                            info.size = member.size
                            reader = _HashingReader(extracted, member.size)
                            out_tar.addfile(info, reader)
                            if reader.bytes_read != member.size:
                                raise ScanError(
                                    "layer_invalid",
                                    f"图层 {layer_path} 正文长度与头部不一致",
                                )
                        finally:
                            extracted.close()
                        original_digests[layer_path] = reader.digest.hexdigest()

                    with patch_tmp.open("rb") as patch_handle:
                        _write_blob(
                            out_tar,
                            patch_layer_path,
                            _ChunkCapReader(patch_handle, len(patch_bytes)),
                            len(patch_bytes),
                            mtime=0,
                        )

        # Phase 5: verify the complete archive before it can ever be served.
        _verify_output(
            output_tmp,
            layer_paths=layer_paths,
            original_digests=original_digests,
            patch_layer_path=patch_layer_path,
            patch_digest=patch_digest,
            new_config_path=new_config_path,
            selected=selected,
        )

        os.replace(output_tmp, output_path)
    except Exception:
        # No downloadable fragment may survive a failed build.
        if output_tmp.exists():
            output_tmp.unlink()
        raise
    finally:
        if patch_tmp.exists():
            patch_tmp.unlink()

    return RepairReport(
        selected=selected,
        layer_paths=layer_paths,
        patch_layer_path=patch_layer_path,
        patch_diff_id=patch_diff_id,
        old_config_path=old_config_path,
        new_config_path=new_config_path,
        output_path=output_path,
        output_size=output_path.stat().st_size,
        original_digests=original_digests,
    )
