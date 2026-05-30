"""
源码解析服务 — ZIP 解压与依赖文件提取
────────────────────────────────────────────────────────────────────────────
职责：
  1. 解压用户上传的 ZIP 源码包到临时工作目录
  2. 遍历目录树，提取 C/C++ 依赖声明文件（CMakeLists.txt / Makefile /
     conanfile.txt / vcpkg.json）和 #include 引用列表
  3. 构建 SourceContext 对象，供 Agent A / Agent B 接口调用时作为请求体

输出 SourceContext 包含的信息：
  - 解压后的源码根目录路径（绝对路径）
  - 依赖声明文件内容列表（供 Agent A 依赖分析）
  - 所有 .c / .cpp / .h 文件的路径列表（供 Agent B 语义审计）
  - #include 引用摘要（辅助 Agent A 猜测引入的第三方库）
"""
import logging
import os
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ── 支持识别的依赖声明文件名（全小写匹配）────────────────────────────────────
_DEP_FILE_NAMES = {
    "cmakelists.txt",
    "makefile",
    "makefile.am",
    "configure.ac",
    "conanfile.txt",
    "conanfile.py",
    "vcpkg.json",
    ".vcpkg-configuration.json",
    "meson.build",
    "build.gradle",
}

# ── C/C++ 源码文件扩展名 ──────────────────────────────────────────────────────
_CPP_EXTENSIONS = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hh", ".hxx"}

# ── 从 #include 提取库名的正则（非系统头文件：< 开头且 / 分隔 or 含点）─────────
_INCLUDE_PATTERN = re.compile(
    r'^\s*#\s*include\s+[<"]([^>"]+)[>"]', re.MULTILINE
)


@dataclass
class SourceContext:
    """解析后的源码上下文，供 Worker 任务传递给 ML Agent 接口"""

    # 解压后的源码根目录（绝对路径字符串）
    source_root: str

    # 原始 ZIP 文件路径（用于溯源）
    zip_path: Optional[str] = None

    # 依赖声明文件内容列表（供 Agent A 进行依赖分析）
    # 每项：{"filename": "CMakeLists.txt", "content": "...", "path": "..."}
    dep_files: list[dict] = field(default_factory=list)

    # C/C++ 源文件路径列表（相对于 source_root）
    cpp_files: list[str] = field(default_factory=list)

    # 所有 #include 引用集合（去重），辅助 Agent A 猜测第三方库
    includes: list[str] = field(default_factory=list)

    # 整个目录树（相对路径列表，供 Agent B 文件选择）
    file_tree: list[str] = field(default_factory=list)


def extract_zip(zip_path: str, extract_to: Optional[str] = None) -> str:
    """
    解压 ZIP 文件到指定目录。

    Args:
        zip_path: ZIP 文件的绝对路径
        extract_to: 解压目标目录，默认与 ZIP 同目录下同名子文件夹

    Returns:
        解压后的根目录路径（字符串）

    Raises:
        ValueError: ZIP 文件无效或路径不合法
        zipfile.BadZipFile: ZIP 文件损坏
    """
    zip_path_obj = Path(zip_path)
    if not zip_path_obj.exists():
        raise ValueError(f"ZIP 文件不存在: {zip_path}")
    if not zipfile.is_zipfile(zip_path):
        raise ValueError(f"文件不是合法的 ZIP 格式: {zip_path}")

    # 默认解压到同目录下的 `<filename>_extracted/` 子目录
    if extract_to is None:
        extract_to = str(zip_path_obj.parent / (zip_path_obj.stem + "_extracted"))

    extract_path = Path(extract_to)
    extract_path.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(zip_path, "r") as zf:
        # 安全检查：防止 zip-slip（路径穿越攻击）
        for member in zf.namelist():
            member_path = extract_path / member
            if not str(member_path.resolve()).startswith(str(extract_path.resolve())):
                raise ValueError(f"ZIP 内包含危险的路径穿越文件名: {member}")
        zf.extractall(extract_path)

    # 如果解压后只有一个顶层目录（常见的 GitHub 下载 zip 格式），进入该目录
    entries = list(extract_path.iterdir())
    if len(entries) == 1 and entries[0].is_dir():
        effective_root = str(entries[0])
    else:
        effective_root = str(extract_path)

    logger.info(f"[SourceParser] ZIP 解压完成 -> {effective_root}")
    return effective_root


def parse_source_context(source_root: str, zip_path: Optional[str] = None) -> SourceContext:
    """
    遍历解压后的源码目录，提取依赖声明文件、C/C++ 文件列表和 #include 引用。

    Args:
        source_root: 解压后的源码根目录
        zip_path: 原始 ZIP 路径（可选，仅用于记录）

    Returns:
        SourceContext 对象
    """
    root = Path(source_root)
    if not root.exists():
        raise ValueError(f"源码目录不存在: {source_root}")

    ctx = SourceContext(source_root=source_root, zip_path=zip_path)
    includes_set: set[str] = set()

    for file_path in root.rglob("*"):
        if not file_path.is_file():
            continue

        # 跳过隐藏目录和常见不需要扫描的目录（加速处理）
        parts = file_path.parts
        if any(p.startswith(".") or p in ("__pycache__", "node_modules", ".git") for p in parts):
            continue

        rel_path = str(file_path.relative_to(root))
        ctx.file_tree.append(rel_path)

        # ── 检查是否为依赖声明文件 ────────────────────────────────────────────
        if file_path.name.lower() in _DEP_FILE_NAMES:
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
                ctx.dep_files.append({
                    "filename": file_path.name,
                    "path": rel_path,
                    "content": content[:8000],  # 截断防止过长，8KB 足够 Agent A 使用
                })
                logger.debug(f"[SourceParser] 发现依赖文件: {rel_path}")
            except Exception as e:
                logger.warning(f"[SourceParser] 读取依赖文件失败 {rel_path}: {e}")

        # ── 检查是否为 C/C++ 源码文件 ─────────────────────────────────────────
        if file_path.suffix.lower() in _CPP_EXTENSIONS:
            ctx.cpp_files.append(rel_path)

            # 提取 #include 引用（只读前 200 行，性能优化）
            try:
                lines = []
                with open(file_path, encoding="utf-8", errors="replace") as f:
                    for i, line in enumerate(f):
                        if i >= 200:
                            break
                        lines.append(line)
                content_head = "".join(lines)
                for inc in _INCLUDE_PATTERN.findall(content_head):
                    includes_set.add(inc)
            except Exception as e:
                logger.debug(f"[SourceParser] 提取 include 失败 {rel_path}: {e}")

    ctx.includes = sorted(includes_set)

    logger.info(
        f"[SourceParser] 解析完成: 依赖文件={len(ctx.dep_files)}, "
        f"C/C++文件={len(ctx.cpp_files)}, #include={len(ctx.includes)}"
    )
    return ctx


def parse_zip_source(zip_path: str) -> SourceContext:
    """
    便捷入口：解压 ZIP 并返回完整的 SourceContext。

    Args:
        zip_path: 上传的 ZIP 文件路径

    Returns:
        SourceContext 对象，包含解压后路径 + 依赖信息
    """
    source_root = extract_zip(zip_path)
    return parse_source_context(source_root, zip_path=zip_path)
