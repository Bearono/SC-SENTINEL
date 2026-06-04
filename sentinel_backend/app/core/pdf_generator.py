"""
PDF 审计报告生成器
使用 ReportLab 生成可下载的 PDF 格式漏洞审计报告。
此模块负责将数据库中的审计结果序列化为 PDF 字节流，
供 GET /api/v1/tasks/{task_id}/export-pdf 接口调用。

执行手册出处：
  ML 同学 B 任务分配 → "PDF 报告导出：使用 WeasyPrint 或 ReportLab 生成可下载的 PDF 审计报告"
  页面三顶部概览卡片 → "下载 PDF 按钮"
"""
import io
from datetime import datetime, timezone
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.pdfbase.ttfonts import TTFont

from app.models.component_risk import ComponentRisk, Severity
from app.models.ebpf_event_log import EbpfEventLog
from app.models.task import Task
from app.models.vulnerability import Vulnerability, VerifyStatus

# ── 中文字体注册 ──────────────────────────────────────────────────────────────
# ReportLab 内置 CID 字体 STSong-Light 可直接渲染中文，无需附带 TTF 文件，
# 避免 Helvetica/Courier 渲染中文时出现乱码（空白方块）。
_CJK_FONT = "Helvetica"        # 西文/默认回退
_CJK_FONT_BOLD = "Helvetica-Bold"
_MONO_FONT = "Courier"

try:
    pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))
    _CJK_FONT = "STSong-Light"
    _CJK_FONT_BOLD = "STSong-Light"   # CID 字体无独立 Bold，复用同一字体
    _MONO_FONT = "STSong-Light"       # 等宽列也用中文字体，保证中文不乱码
except Exception:
    # 注册失败时回退到内置西文字体（中文会丢失，但不致命）
    pass

# ── 颜色常量（来自执行手册配色规范） ────────────────────────────────────────────
COLOR_DARK_BLUE = colors.HexColor("#1A3A5C")    # 深蓝主色
COLOR_ACCENT    = colors.HexColor("#EF9F27")    # 强调色（警告/高危）
COLOR_SUCCESS   = colors.HexColor("#1D9E75")    # 成功色（低危/已确认）
COLOR_DANGER    = colors.HexColor("#D9534F")    # 严重危险（Critical）
COLOR_MID       = colors.HexColor("#E8A838")    # 中危
COLOR_LIGHT_BG  = colors.HexColor("#F4F6F9")    # 浅灰背景

# ── 危险等级颜色映射 ──────────────────────────────────────────────────────────
SEVERITY_COLORS = {
    Severity.CRITICAL: COLOR_DANGER,
    Severity.HIGH:     COLOR_ACCENT,
    Severity.MEDIUM:   COLOR_MID,
    Severity.LOW:      COLOR_SUCCESS,
    Severity.UNKNOWN:  colors.grey,
}

# ── 验证状态文字映射 ──────────────────────────────────────────────────────────
VERIFY_STATUS_LABELS = {
    VerifyStatus.CONFIRMED:     "已确认",
    VerifyStatus.UNVERIFIED:    "待验证",
    VerifyStatus.FALSE_POSITIVE: "误报",
}


def _get_styles():
    """构建 PDF 样式表（使用 CJK 字体 STSong-Light，确保中文不乱码）"""
    base = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "SentinelTitle",
        parent=base["Title"],
        fontName=_CJK_FONT_BOLD,
        fontSize=22,
        leading=28,
        textColor=COLOR_DARK_BLUE,
        alignment=TA_CENTER,
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "SentinelSubtitle",
        parent=base["Normal"],
        fontName=_CJK_FONT,
        fontSize=11,
        textColor=colors.grey,
        alignment=TA_CENTER,
        spaceAfter=16,
    )
    section_style = ParagraphStyle(
        "SentinelSection",
        parent=base["Heading2"],
        fontName=_CJK_FONT_BOLD,
        fontSize=13,
        leading=18,
        textColor=COLOR_DARK_BLUE,
        spaceBefore=14,
        spaceAfter=6,
        borderPad=3,
    )
    body_style = ParagraphStyle(
        "SentinelBody",
        parent=base["Normal"],
        fontName=_CJK_FONT,
        fontSize=9,
        leading=14,
        textColor=colors.HexColor("#333333"),
    )
    meta_style = ParagraphStyle(
        "SentinelMeta",
        parent=base["Normal"],
        fontName=_CJK_FONT,
        fontSize=8,
        textColor=colors.grey,
        alignment=TA_LEFT,
    )
    code_style = ParagraphStyle(
        "SentinelCode",
        parent=base["Code"],
        fontName=_MONO_FONT,
        fontSize=7.5,
        leading=11,
        backColor=colors.HexColor("#1E1E1E"),
        textColor=colors.HexColor("#D4D4D4"),
        borderPad=6,
        leftIndent=6,
        rightIndent=6,
    )
    return {
        "title":    title_style,
        "subtitle": subtitle_style,
        "section":  section_style,
        "body":     body_style,
        "meta":     meta_style,
        "code":     code_style,
    }


def _severity_badge(severity: Severity) -> str:
    """返回带颜色标注的危险等级文字（ReportLab XML 格式）"""
    label_map = {
        Severity.CRITICAL: "CRITICAL",
        Severity.HIGH:     "HIGH",
        Severity.MEDIUM:   "MEDIUM",
        Severity.LOW:      "LOW",
        Severity.UNKNOWN:  "UNKNOWN",
    }
    color_map = {
        Severity.CRITICAL: "#D9534F",
        Severity.HIGH:     "#EF9F27",
        Severity.MEDIUM:   "#E8A838",
        Severity.LOW:      "#1D9E75",
        Severity.UNKNOWN:  "#888888",
    }
    label = label_map.get(severity, "UNKNOWN")
    color = color_map.get(severity, "#888888")
    return f'<font color="{color}"><b>[{label}]</b></font>'


def generate_audit_pdf(task: Task) -> bytes:
    """
    接收一个已预加载全部关联数据的 Task ORM 对象，
    生成完整的 PDF 审计报告，返回 bytes 字节流。

    调用前提：task.component_risks 和 task.vulnerabilities（含 ebpf_events）
    均已通过 selectinload 预加载完毕。
    """
    buffer = io.BytesIO()
    styles = _get_styles()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
        title=f"SENTINEL 漏洞审计报告 - {task.project_name}",
        author="SENTINEL System",
        subject="C/C++ 供应链安全审计报告",
    )

    elements = []

    # ════════════════════════════════════════════════════════════════════════════
    # 封面区域
    # ════════════════════════════════════════════════════════════════════════════
    elements.append(Spacer(1, 20 * mm))
    elements.append(Paragraph("SENTINEL", styles["title"]))
    elements.append(Paragraph("C/C++ 开源供应链 eBPF-LLM 协同漏洞审计报告", styles["subtitle"]))
    elements.append(HRFlowable(width="100%", thickness=2, color=COLOR_DARK_BLUE))
    elements.append(Spacer(1, 4 * mm))

    # 报告元信息表格
    created_str = task.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if task.created_at else "N/A"
    completed_str = "N/A"
    total_time_str = "N/A"
    if task.completed_at:
        completed_str = task.completed_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        if task.created_at:
            ca = task.created_at
            co = task.completed_at
            if ca.tzinfo is None:
                ca = ca.replace(tzinfo=timezone.utc)
            if co.tzinfo is None:
                co = co.replace(tzinfo=timezone.utc)
            seconds = (co - ca).total_seconds()
            total_time_str = f"{seconds:.1f} 秒"

    meta_data = [
        ["项目名称", task.project_name],
        ["任务 ID", str(task.id)],
        ["创建时间", created_str],
        ["完成时间", completed_str],
        ["审计耗时", total_time_str],
        ["动态验证", "已开启 eBPF 验证" if task.is_dynamic else "仅静态分析"],
        ["发现漏洞数", str(len(task.vulnerabilities))],
        ["组件风险数", str(len(task.component_risks))],
    ]
    meta_table = Table(meta_data, colWidths=[40 * mm, 120 * mm])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (0, -1), COLOR_LIGHT_BG),
        ("TEXTCOLOR",    (0, 0), (0, -1), COLOR_DARK_BLUE),
        ("FONTNAME",     (0, 0), (-1, -1), _CJK_FONT),
        ("FONTSIZE",     (0, 0), (-1, -1), 9),
        ("FONTNAME",     (0, 0), (0, -1), _CJK_FONT_BOLD),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, COLOR_LIGHT_BG]),
        ("GRID",         (0, 0), (-1, -1), 0.5, colors.HexColor("#DDDDDD")),
        ("LEFTPADDING",  (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING",   (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 8 * mm))

    # ════════════════════════════════════════════════════════════════════════════
    # 一、组件风险清单（对应 Agent A 输出）
    # ════════════════════════════════════════════════════════════════════════════
    elements.append(Paragraph("一、第三方组件风险清单", styles["section"]))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CCCCCC")))
    elements.append(Spacer(1, 2 * mm))

    if task.component_risks:
        comp_header = [["组件名称", "版本", "CVE 编号", "CVSS", "危险等级"]]
        comp_rows = []
        for c in task.component_risks:
            comp_rows.append([
                c.library_name or "N/A",
                c.version or "未知",
                c.cve_id or "无",
                f"{c.cvss_score:.1f}" if c.cvss_score else "N/A",
                c.severity.value.upper(),
            ])
        comp_table = Table(comp_header + comp_rows, colWidths=[45 * mm, 25 * mm, 35 * mm, 18 * mm, 37 * mm])

        # 动态行颜色：根据危险等级高亮
        row_styles = [
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_DARK_BLUE),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("FONTNAME",   (0, 0), (-1, 0), _CJK_FONT_BOLD),
            ("FONTNAME",   (0, 1), (-1, -1), _CJK_FONT),
            ("FONTSIZE",   (0, 0), (-1, -1), 8),
            ("GRID",       (0, 0), (-1, -1), 0.5, colors.HexColor("#DDDDDD")),
            ("LEFTPADDING",  (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING",   (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 3),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, COLOR_LIGHT_BG]),
        ]
        for i, c in enumerate(task.component_risks, start=1):
            sev_color = SEVERITY_COLORS.get(c.severity, colors.grey)
            row_styles.append(("TEXTCOLOR", (4, i), (4, i), sev_color))
            row_styles.append(("FONTNAME",  (4, i), (4, i), _CJK_FONT_BOLD))

        comp_table.setStyle(TableStyle(row_styles))
        elements.append(comp_table)
    else:
        elements.append(Paragraph("本次审计未识别到第三方组件风险。", styles["body"]))

    elements.append(Spacer(1, 8 * mm))

    # ════════════════════════════════════════════════════════════════════════════
    # 二、漏洞详情清单（对应 Agent B/C 输出）
    # ════════════════════════════════════════════════════════════════════════════
    elements.append(Paragraph("二、漏洞详情清单", styles["section"]))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CCCCCC")))
    elements.append(Spacer(1, 2 * mm))

    if task.vulnerabilities:
        for idx, v in enumerate(task.vulnerabilities, start=1):
            # 漏洞标题行
            verify_label = VERIFY_STATUS_LABELS.get(v.verify_status, "未知")
            title_text = (
                f"<b>#{idx} [{v.vuln_type}]</b> &nbsp;&nbsp; "
                f"{v.file_path or 'N/A'}:{v.line_number or 'N/A'} &nbsp;&nbsp; "
                f"验证状态: <b>{verify_label}</b>"
            )
            elements.append(Paragraph(title_text, styles["body"]))

            # 代码片段
            if v.code_context:
                code_text = v.code_context.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                elements.append(Spacer(1, 1 * mm))
                elements.append(Paragraph(f"<pre>{code_text}</pre>", styles["code"]))

            # 触发条件 + 修复建议
            detail_data = []
            if v.trigger_cond:
                detail_data.append(["触发条件", v.trigger_cond])
            if v.fix_advice:
                detail_data.append(["修复建议", v.fix_advice])
            if detail_data:
                detail_table = Table(detail_data, colWidths=[22 * mm, 138 * mm])
                detail_table.setStyle(TableStyle([
                    ("BACKGROUND",    (0, 0), (0, -1), COLOR_LIGHT_BG),
                    ("FONTNAME",      (0, 0), (0, -1), _CJK_FONT_BOLD),
                    ("FONTNAME",      (1, 0), (1, -1), _CJK_FONT),
                    ("FONTSIZE",      (0, 0), (-1, -1), 8),
                    ("GRID",          (0, 0), (-1, -1), 0.4, colors.HexColor("#EEEEEE")),
                    ("LEFTPADDING",   (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
                    ("TOPPADDING",    (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                    ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                ]))
                elements.append(Spacer(1, 1 * mm))
                elements.append(detail_table)

            # eBPF 事件日志
            if v.ebpf_events:
                elements.append(Spacer(1, 1 * mm))
                elements.append(Paragraph("<b>eBPF 内核事件日志：</b>", styles["body"]))
                ebpf_header = [["时间戳 (ns)", "事件类型", "函数", "内存地址"]]
                ebpf_rows = [
                    [
                        str(e.timestamp),
                        e.event_type.value,
                        e.function_name or "N/A",
                        e.memory_addr or "N/A",
                    ]
                    for e in v.ebpf_events
                ]
                ebpf_table = Table(ebpf_header + ebpf_rows, colWidths=[40 * mm, 35 * mm, 40 * mm, 45 * mm])
                ebpf_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2D2D2D")),
                    ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#1E1E1E")),
                    ("TEXTCOLOR",  (0, 1), (-1, -1), colors.HexColor("#D4D4D4")),
                    ("FONTNAME",   (0, 0), (-1, -1), "Courier"),
                    ("FONTSIZE",   (0, 0), (-1, -1), 7),
                    ("GRID",       (0, 0), (-1, -1), 0.3, colors.HexColor("#444444")),
                    ("LEFTPADDING",  (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING",   (0, 0), (-1, -1), 2),
                    ("BOTTOMPADDING",(0, 0), (-1, -1), 2),
                ]))
                elements.append(ebpf_table)

            elements.append(HRFlowable(width="100%", thickness=0.3, color=colors.HexColor("#EEEEEE")))
            elements.append(Spacer(1, 3 * mm))
    else:
        elements.append(Paragraph("本次审计未发现任何漏洞。", styles["body"]))

    elements.append(Spacer(1, 6 * mm))

    # ════════════════════════════════════════════════════════════════════════════
    # 页脚声明
    # ════════════════════════════════════════════════════════════════════════════
    elements.append(HRFlowable(width="100%", thickness=1, color=COLOR_DARK_BLUE))
    elements.append(Spacer(1, 2 * mm))
    footer_text = (
        f"本报告由 SENTINEL 自动生成 · CISCN 2025 · "
        f"生成时间: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
    )
    elements.append(Paragraph(footer_text, styles["meta"]))

    doc.build(elements)
    return buffer.getvalue()
