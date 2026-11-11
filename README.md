# 镜像 SUID / SGID 审计与降权修复

发布镜像前，用一个只读的 Docker 层合并视图找出最终仍带 **SUID** 或 **SGID** 位的普通文件，并定位最后一次写入该文件的镜像层。容器运维人员确认后，可在同一页面勾选文件并生成一个**可重新 `docker load` 导入的降权镜像 tar**。

页面使用 FastAPI，上传 `docker save` 导出的**单镜像 tar**，按 `manifest.json` 中 `Layers` 的顺序合并元数据。内置四层示例可直接扫描或下载。

## 降权修复如何工作

1. 扫描结果表格中勾选需要降权的文件（支持全选），点击「生成降权镜像」。
2. 浏览器把**原始归档**与所选路径再次提交，服务端重新跑一遍完整的层合并核对——不依赖上一次扫描结果。
3. **任一所选路径不是最终仍带 SUID/SGID 位的普通文件，整批拒绝**，不产生任何输出字节。
4. 通过核对后，服务端**追加一个新的未压缩补丁层**，对每个所选文件：
   - 复制其在最后写入层中的**最后有效版本正文**与 **UID/GID**；
   - 仅清除 SUID/SGID 两个特殊位，保留其余权限位（含 sticky 位与 rwx）；
5. 原图层成员按字节原样复制（生成后用 sha256 回读校验），未选文件与原层字节均不变。
6. 同步更新镜像 config 的 `rootfs.diff_ids`、`history`，按内容摘要重写 config 文件名（`blobs/sha256/<digest>`），并更新 `manifest.json` 的 `Config` / `Layers` 引用；运行配置（Env/Cmd/Entrypoint/WorkingDir/User 等）与标签原样保留。
7. 完整生成并通过校验后，归档才以原子重命名开放下载；任何失败都会删除临时残片，下载接口只可能返回完整归档。

整个过程**不执行镜像、不解包文件到文件系统**；所有正文都以固定 1 MiB 分块流式复制，内存占用不随镜像大小增长。

### 输入约束（修复接口）

修复仅接受**外层 tar 与每一个图层 tar 都未压缩**的单镜像 `docker save` 归档。gzip/xz/bzip2/zstd 压缩的外层或图层会被明确拒绝（`compressed_unsupported`）。扫描接口仍可只读解析压缩图层，但不会对其生成修复归档。

可按如下方式导出未压缩的单镜像归档：

```bash
docker save <image> -o image.tar
```

## 快速启动

```bash
docker compose up --build
```

打开 <http://localhost:8000>。若 8000 端口被占用：

```bash
APP_PORT=8080 docker compose up --build
```

停止：

```bash
docker compose down
```

Compose 以非 root 用户运行，容器根文件系统只读，丢弃全部 capabilities，并启用 `no-new-privileges`。上传暂存与修复产物都位于容器内 `/tmp` tmpfs（默认 1 GiB）；归档和层**内容不会被解包**到宿主或容器文件系统。修复任务产物默认保留 1 小时、最多 20 个，可用 `PRIV_AUDIT_JOB_TTL` / `PRIV_AUDIT_JOB_MAX` 调整。

## 页面功能

- 拖拽或选择 `docker save` 单镜像 tar。
- 一键扫描内置四层示例。
- 列出最终 SUID/SGID 普通文件的路径、八进制权限、UID/GID、最后写入层。
- 显示层顺序、manifest 索引和 layer digest。
- 勾选一个或多个高权限文件（含全选），生成追加降权补丁层的修复归档。
- 完整生成并校验通过后开放下载；失败时显示原因且不留下可下载残片。
- 一键扫描刚生成的修复归档，核对特权位已清除且 UID/GID/正文不变。
- 错误会明确区分：hardlink 不支持、越界路径、符号链接层引用、多个镜像、无效 manifest、压缩归档/图层、批量选择不合格等。

## API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/` | 网页 |
| `POST` | `/api/scan` | 上传 tar，表单字段 `archive`（兼容 `image` / `file`） |
| `POST` | `/api/repair` | 上传原 tar + 所选路径，生成降权归档；路径用重复的 `paths` 字段或 `paths_json`（JSON 字符串数组） |
| `POST` | `/api/demo/repair` | 对内置示例执行降权修复（无需再传归档），表单字段同上 |
| `GET` | `/api/repair/jobs/{id}` | 查询修复任务状态 |
| `GET` | `/api/repair/jobs/{id}/download` | 下载完整生成的降权 tar（`attachment`） |
| `POST` | `/api/repair/jobs/{id}/scan` | 扫描已生成的降权归档以核对结果 |
| `GET` | `/api/demo` | 扫描内置示例，返回与上传相同结构 |
| `GET` | `/api/demo/archive` | 下载内置示例 tar |
| `GET` | `/api/openapi.json` | OpenAPI 描述 |
| `GET` | `/healthz` | 健康检查 |

### 修复请求与响应

```bash
curl -sS -F archive=@image.tar \
  -F 'paths_json=["usr/bin/ping","usr/bin/wall"]' \
  http://localhost:8000/api/repair | jq
```

成功响应节选：

```json
{
  "status": "complete",
  "job": {
    "job_id": "llEAVCYfNy22MeCYOgWVXw",
    "download_name": "image-privilege-fixed-llEAVCYf.tar",
    "download_url": "/api/repair/jobs/llEAVCYfNy22MeCYOgWVXw/download",
    "report": {
      "selected_count": 2,
      "patch_layer": {
        "path": "blobs/sha256/2bb2c43b…",
        "diff_id": "sha256:2bb2c43b…"
      },
      "config": {"old_path": "blobs/sha256/902664fa…", "new_path": "blobs/sha256/…"},
      "selected_files": [
        {
          "path": "/usr/bin/ping",
          "old_mode_octal": "4755",
          "new_mode_octal": "0755",
          "uid": 0, "gid": 0, "size": 14,
          "body_digest": "sha256:…"
        }
      ]
    }
  }
}
```

批量选择不合格时整批拒绝（HTTP 400），且不产生任何任务产物：

```json
{
  "detail": {
    "code": "selection_not_privileged_regular",
    "message": "所选路径不是最终仍带 SUID/SGID 位的高权限普通文件；整批修复已拒绝",
    "path": "/etc/motd",
    "layer_number": 1
  }
}
```

下载后可直接导入并核对：

```bash
curl -o fixed.tar "$(jq -r '.job.download_url' < repair.json | sed 's#^#http://localhost:8000#')"
docker load -i fixed.tar
```

响应节选：

```json
{
  "source": "upload",
  "image": {"tags": ["demo/privilege-audit:latest"], "config_path": "blobs/sha256/..."},
  "layers": [
    {"number": 1, "manifest_index": 0, "path": "blobs/sha256/...", "name": "sha256:..."}
  ],
  "files": [
    {
      "path": "/usr/bin/ping",
      "relative_path": "usr/bin/ping",
      "mode": 2541,
      "mode_octal": "4755",
      "permissions": "4755",
      "uid": 0,
      "gid": 0,
      "special_bits": ["SUID"],
      "file_type": "regular",
      "last_layer": {
        "number": 2,
        "manifest_index": 1,
        "path": "blobs/sha256/...",
        "name": "sha256:..."
      },
      "layer_number": 2,
      "layer_manifest_index": 1
    }
  ],
  "summary": {
    "layers_scanned": 4,
    "privileged_files": 5,
    "suid_files": 2,
    "sgid_files": 3
  }
}
```

- `number` 是便于阅读的 1-based 层号。
- `manifest_index` 是 `manifest.json` 中 `Layers` 数组的 0-based 下标。
- `mode` 是权限位整数，`mode_octal` 是补足四位的八进制字符串（如 `4755`）。

错误响应采用 FastAPI 的 `detail` 对象：

```json
{
  "detail": {
    "code": "hardlink_unsupported",
    "message": "不支持硬链接（hard link）：/hard（层 2）",
    "path": "/hard",
    "layer_number": 2,
    "layer_path": "blobs/sha256/..."
  }
}
```

## 合并规则

1. **严格按 manifest 顺序**逐层应用，先应用较低层，再应用较高层。
2. **普通 whiteout**（如 `dir/.wh.file`）只从已继承的低层视图中删除 `dir/file` 及其子树。
3. **opaque whiteout**（`dir/.wh..wh..opq`）只清空低层目录 `dir/` 的内容，目录节点和本层新增内容保留。
4. **whiteout 与同层新增分离处理**：先对低层应用全部 whiteout，再添加本层条目。因此无论 `.wh.*` 在 tar 中排在本层新文件之前还是之后，结果一致。
5. **目录/文件互换**：
   - 上层普通文件、符号链接或特殊文件替换低层目录时，低层整棵子树被遮蔽。
   - 上层目录替换低层普通文件时，低层文件消失，子项按新层建立。
6. **符号链接不跟随**：只记录符号链接本身，不解析 `linkname`，更不会把目标文件或链接目标算作普通文件。
7. **硬链接明确拒绝**：层内出现 hardlink 立即返回 `hardlink_unsupported`，而不是猜测目标元数据。
8. **越界路径拒绝**：绝对路径、包含 `..` 的路径、NUL 字节路径都会失败，不会静默改写路径。

最终仅列出满足以下条件的条目：

- 类型为普通文件（`regular file`）；
- 权限位包含 `0o4000`（SUID）或 `0o2000`（SGID）；
- 未被更高层删除、遮蔽或替换。

## 安全设计

- 只调用 `tarfile` 读取外层归档与内层层 tar 的头/成员流。
- 没有 `extract()`、`extractall()`，也不会写入任何解包后的文件；修复产物是逐块重写的新 tar，而非解包后重新打包。
- 层 tar 通过流式 `r|*` 读取，扫描支持未压缩、gzip、xz、bz2 层；修复路径强制 `r:`/`r|` 未压缩并在读取魔数阶段拒绝压缩输入。
- 所有成员路径在合并前校验；符号链接层引用会被拒绝。
- 不解析符号链接、不跟随硬链接。
- 修复正文统一经 1 MiB 上限的分块 reader 复制，并对原图层字节、补丁层字节、config 摘要、manifest 引用做生成后回读校验。
- 输出 tar 先写入私有 `work/` 临时文件，校验通过后 `os.replace` 原子发布；失败即删除临时文件，下载接口只服务完整归档。
- 服务容器只读、非 root、`cap_drop: ALL`、`no-new-privileges`；任务产物位于 tmpfs 并按 TTL/数量自动清理。
- UI 使用 `textContent` 渲染扫描结果，避免镜像内恶意路径造成 XSS；并设置 CSP。

> 上传文件本身由 ASGI/Starlette 暂存（默认超过 1 MiB 会落到 `/tmp`），修复接口再以 1 MiB 分块转存到独立临时文件。Compose 把 `/tmp` 挂为 tmpfs；这只是上传字节与最终 tar 的暂存，不是归档解包。若处理较大的真实镜像，可通过 `UPLOAD_TMP_SIZE` 调整 tmpfs 大小。

## 本地开发与测试

无需 Docker 的合并逻辑测试：

```bash
python3 -m unittest discover -s tests -v
```

运行 Web 服务：

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

重新生成内置示例：

```bash
python3 app/sample.py examples/multilayer-demo.tar
```

## 目录结构

```text
app/
  main.py        FastAPI 路由、上传、修复任务与下载
  merger.py      只读 tar 解析、层合并、SUID/SGID 收集、压缩识别
  repair.py      选择核对、补丁层构建、config/manifest 重写、生成后校验
  jobs.py        修复任务的原子发布、TTL 清理与下载管理
  sample.py      内存中生成四层 docker-save 示例
  static/        网页、样式和前端逻辑
examples/        内置示例 tar 与说明
tests/           合并规则、修复流程与安全边界测试
Dockerfile
docker-compose.yml
```

## 已知边界

- 仅支持单镜像 `docker save` 格式；多镜像归档会明确拒绝。
- **修复接口仅支持外层与图层均未压缩的 tar**；压缩输入返回 `compressed_unsupported`。扫描接口仍可只读识别压缩图层。
- 硬链接不受支持（按需求明确报错），因此含 hardlink 的镜像不会给出部分结果或修复产物。
- 降权只清除 SUID/SGID；sticky 位、普通 rwx 位、UID/GID 与文件正文保持不变。
- 不解析镜像 config 中的 `User`、capabilities 或 seccomp 配置；本工具审计与修复的是文件权限位。
- 不把文件名解析到容器用户数据库，故 UID/GID 以数字展示。
- 修复任务产物保存在容器 tmpfs 中，重启容器或超过 TTL 后失效，需要重新发起修复。
