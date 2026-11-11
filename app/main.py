from __future__ import annotations

import asyncio
import contextlib
import io
import json
import logging
import os
import tempfile
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

from app.jobs import JobError, JobStore
from app.merger import ScanError, scan_docker_archive
from app.repair import repair_archive
from app.sample import build_demo_archive

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
JOB_ROOT = Path(os.environ.get("PRIV_AUDIT_JOB_DIR", "/tmp/privilege-audit-jobs"))

job_store = JobStore(JOB_ROOT)


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    await run_in_threadpool(job_store.cleanup)

    async def _periodic_cleanup() -> None:
        while True:
            await asyncio.sleep(600)
            try:
                await run_in_threadpool(job_store.cleanup)
            except Exception:  # defensive: cleanup must never kill the loop
                logger.exception("Scheduled job cleanup failed")

    task = asyncio.create_task(_periodic_cleanup())
    try:
        yield
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


app = FastAPI(
    title="镜像 SUID / SGID 审计与降权修复",
    description="只读解析 docker save 单镜像 tar，按层合并 whiteout 后定位高权限普通文件，并生成追加补丁层的降权镜像。",
    version="2.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; base-uri 'none'; "
        "form-action 'self'; frame-ancestors 'none'"
    )
    return response


def _scan_error(exc: ScanError) -> HTTPException:
    return HTTPException(status_code=400, detail=exc.to_detail())


async def _scan_upload(upload: UploadFile) -> dict:
    try:
        result = await run_in_threadpool(scan_docker_archive, upload.file)
    except ScanError as exc:
        raise _scan_error(exc) from exc
    except Exception as exc:  # defensive: never expose a stack trace to the client
        logger.exception("Unexpected archive scan failure")
        raise HTTPException(
            status_code=500,
            detail={
                "code": "scan_failed",
                "message": f"扫描失败：{type(exc).__name__}",
            },
        ) from exc
    return result.as_dict(source="upload")


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/healthz", include_in_schema=False)
async def healthz() -> dict:
    return {"status": "ok"}


@app.post("/api/scan", summary="扫描上传的 docker save 单镜像 tar")
@app.post("/scan", include_in_schema=False)
async def scan_archive(
    archive: UploadFile | None = File(default=None),
    image: UploadFile | None = File(default=None),
    file: UploadFile | None = File(default=None),
) -> dict:
    upload = archive or image or file
    if upload is None:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "file_missing",
                "message": "请上传 docker save 导出的单镜像 tar 文件（表单字段 archive、image 或 file）",
            },
        )
    try:
        return await _scan_upload(upload)
    finally:
        await upload.close()


def _spool_upload(upload: UploadFile):
    """Persist upload bytes into an isolated temp file for repeated passes."""

    handle = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024, dir="/tmp")
    try:
        while True:
            chunk = upload.file.read(1024 * 1024)
            if not chunk:
                break
            handle.write(chunk)
        handle.seek(0)
    except Exception:
        handle.close()
        raise
    return handle


def _run_repair(fileobj, paths: list[str], job_id: str, work_dir: Path):
    output_path = job_store.output_path_for(job_id)
    return repair_archive(fileobj, paths, output_path, work_dir=work_dir)


@app.post("/api/repair", summary="生成追加降权补丁层的可重新导入镜像 tar")
@app.post("/repair", include_in_schema=False)
async def repair_upload(
    paths: list[str] = Form(default=[]),
    paths_json: str | None = Form(default=None),
    archive: UploadFile | None = File(default=None),
    image: UploadFile | None = File(default=None),
    file: UploadFile | None = File(default=None),
) -> dict:
    upload = archive or image or file
    if upload is None:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "file_missing",
                "message": "请重新上传需要修复的 docker save 单镜像 tar（表单字段 archive、image 或 file）",
            },
        )

    selected_paths = list(paths)
    if paths_json:
        try:
            decoded = json.loads(paths_json)
        except json.JSONDecodeError as exc:
            raise HTTPException(
                status_code=400,
                detail={
                    "code": "selection_invalid",
                    "message": f"paths_json 不是有效的 JSON 数组：{exc}",
                },
            ) from exc
        if not isinstance(decoded, list) or any(not isinstance(item, str) for item in decoded):
            raise HTTPException(
                status_code=400,
                detail={
                    "code": "selection_invalid",
                    "message": "paths_json 必须是字符串数组",
                },
            )
        selected_paths.extend(decoded)

    job_id, work_dir = job_store.new_work_dir()
    spool = None
    try:
        spool = await run_in_threadpool(_spool_upload, upload)
        report = await run_in_threadpool(
            _run_repair, spool, selected_paths, job_id, work_dir
        )
        record = job_store.publish(
            job_id, archive_name=upload.filename or "image.tar", report=report.as_dict()
        )
        job_store.discard_work(job_id)
    except ScanError as exc:
        job_store.discard_work(job_id)
        raise _scan_error(exc) from exc
    except JobError as exc:
        job_store.discard_work(job_id)
        raise HTTPException(status_code=exc.status_code, detail={"code": exc.code, "message": exc.message}) from exc
    except Exception as exc:
        logger.exception("Unexpected repair failure")
        job_store.discard_work(job_id)
        raise HTTPException(
            status_code=500,
            detail={
                "code": "repair_failed",
                "message": f"修复失败：{type(exc).__name__}，未生成任何可下载归档",
            },
        ) from exc
    finally:
        if spool is not None:
            spool.close()
        await upload.close()

    return {
        "status": "complete",
        "source": "upload",
        "message": "降权镜像已生成并通过完整校验，可重新 docker load 导入。",
        "job": record.as_dict(),
    }


@app.post("/api/demo/repair", summary="对内置多层示例执行降权修复")
async def repair_demo(
    paths: list[str] = Form(default=[]),
    paths_json: str | None = Form(default=None),
) -> dict:
    selected_paths = list(paths)
    if paths_json:
        try:
            decoded = json.loads(paths_json)
        except json.JSONDecodeError as exc:
            raise HTTPException(
                status_code=400,
                detail={"code": "selection_invalid", "message": f"paths_json 无效：{exc}"},
            ) from exc
        if isinstance(decoded, list):
            selected_paths.extend(item for item in decoded if isinstance(item, str))

    job_id, work_dir = job_store.new_work_dir()
    try:
        payload = await run_in_threadpool(build_demo_archive)
        report = await run_in_threadpool(
            _run_repair, io.BytesIO(payload), selected_paths, job_id, work_dir
        )
        record = job_store.publish(
            job_id, archive_name="privilege-audit-demo.tar", report=report.as_dict()
        )
        job_store.discard_work(job_id)
    except ScanError as exc:
        job_store.discard_work(job_id)
        raise _scan_error(exc) from exc
    except Exception as exc:
        logger.exception("Unexpected demo repair failure")
        job_store.discard_work(job_id)
        raise HTTPException(
            status_code=500,
            detail={
                "code": "repair_failed",
                "message": f"修复失败：{type(exc).__name__}，未生成任何可下载归档",
            },
        ) from exc

    return {
        "status": "complete",
        "source": "built-in-demo",
        "message": "示例降权镜像已生成并通过完整校验。",
        "job": record.as_dict(),
    }


@app.get("/api/repair/jobs/{job_id}", summary="查询修复任务状态")
async def repair_job_status(job_id: str) -> dict:
    try:
        record = job_store.get(job_id)
    except JobError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.code, "message": exc.message},
        ) from exc
    return record.as_dict()


@app.get("/api/repair/jobs/{job_id}/download", summary="下载完整生成的降权镜像 tar")
async def repair_job_download(job_id: str) -> FileResponse:
    try:
        record = job_store.get(job_id)
    except JobError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.code, "message": exc.message},
        ) from exc
    return FileResponse(
        record.archive_path,
        media_type="application/x-tar",
        filename=record.download_name,
        headers={"X-Repair-Job": record.job_id},
    )


@app.post("/api/repair/jobs/{job_id}/scan", summary="扫描已生成的降权镜像以核对结果")
async def repair_job_scan(job_id: str) -> dict:
    try:
        record = job_store.get(job_id)
    except JobError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.code, "message": exc.message},
        ) from exc

    def _scan() -> dict:
        with record.archive_path.open("rb") as handle:
            return scan_docker_archive(handle).as_dict(source="repaired-archive")

    try:
        return await run_in_threadpool(_scan)
    except ScanError as exc:
        raise _scan_error(exc) from exc


def _scan_demo() -> dict:
    try:
        result = scan_docker_archive(io.BytesIO(build_demo_archive()))
    except ScanError as exc:
        raise _scan_error(exc) from exc
    return result.as_dict(source="built-in-demo")


@app.get("/api/demo", summary="扫描内置多层示例")
@app.post("/api/demo", include_in_schema=False)
async def demo_scan() -> dict:
    return await run_in_threadpool(_scan_demo)


@app.get("/api/demo/archive", summary="下载内置多层示例 tar")
async def demo_archive() -> Response:
    payload = await run_in_threadpool(build_demo_archive)
    return Response(
        content=payload,
        media_type="application/x-tar",
        headers={
            "Content-Disposition": 'attachment; filename="privilege-audit-demo.tar"',
            "Content-Length": str(len(payload)),
        },
    )
