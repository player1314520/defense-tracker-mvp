"""
飞书机器人集成模块 v1.1
────────────────────────────────────────────────────
工作流：发消息给飞书机器人 → 自动抓取/解析内容 → AI生成要讯 → 回复卡片
支持：文章链接（自动抓取）/ 文章正文（直接生成）

环境变量配置：
  FEISHU_APP_ID            飞书应用 App ID
  FEISHU_APP_SECRET        飞书应用 App Secret
  FEISHU_VERIFY_TOKEN      飞书事件订阅验证 Token（用于签名校验）
────────────────────────────────────────────────────
"""
import hashlib, hmac, json, os, re, time, logging, threading
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
import requests
from flask import Blueprint, request, jsonify
from docx import Document as DocxDocument
from docx.shared import Pt, Emu
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_LINE_SPACING
from docx.oxml.ns import qn
from feishu_common import (
    ascii_fallback_name as _ascii_fallback_name,
    sanitize_feishu_filename as _sanitize_feishu_filename,
)
from state import CONFIG_DIR

feishu_bp = Blueprint("feishu_bot", __name__)
logger = logging.getLogger(__name__)

# 全局线程池（替代无限 daemon thread，防止线程爆炸）
_worker_pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="feishu_bot")

# ── 飞书应用配置（运行时可通过 /api/feishu/config 接口更新）────
_FEISHU_CONFIG_FILE = os.path.join(CONFIG_DIR, ".feishu_config.json")

def _load_feishu_config() -> dict:
    base = {
        "app_id":       os.environ.get("FEISHU_APP_ID", ""),
        "app_secret":   os.environ.get("FEISHU_APP_SECRET", ""),
        "verify_token": os.environ.get("FEISHU_VERIFY_TOKEN", ""),
    }
    if os.path.exists(_FEISHU_CONFIG_FILE):
        try:
            with open(_FEISHU_CONFIG_FILE, encoding="utf-8") as f:
                saved = json.load(f)
            base.update({k: v for k, v in saved.items() if v})
        except Exception:
            pass
    return base

def _save_feishu_config():
    try:
        with open(_FEISHU_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(FEISHU_CONFIG, f)
    except Exception as e:
        logger.warning("保存飞书配置失败: %s", e)

FEISHU_CONFIG = _load_feishu_config()

FEISHU_API = "https://open.feishu.cn/open-apis"

# ── Token 缓存 ────────────────────────────────────────────────
_token_lock  = threading.Lock()
_token_cache = {"token": "", "expire": 0}

# ── 已处理消息 ID（防飞书重试导致重复生成）─────────────────────
_seen_msg_ids: OrderedDict = OrderedDict()  # msg_id → timestamp，有序淘汰
_seen_lock = threading.Lock()
_MAX_SEEN = 500   # 最多记录500条，防内存无限增长


def _is_new_message(msg_id: str) -> bool:
    """True = 新消息，False = 已处理过（重复）"""
    if not msg_id:
        return True
    with _seen_lock:
        if msg_id in _seen_msg_ids:
            return False
        _seen_msg_ids[msg_id] = time.time()
        while len(_seen_msg_ids) > _MAX_SEEN:
            _seen_msg_ids.popitem(last=False)
    return True


def _verify_feishu_signature(token: str, timestamp: str, nonce: str, body: bytes) -> bool:
    """
    验证飞书事件订阅签名（X-Lark-Signature）。
    算法：sha256(timestamp + nonce + token + body_str)
    token 为飞书开放平台 → 事件订阅 → 验证令牌（Verification Token）。
    """
    if not token:
        return True   # 未配置 token 则跳过校验（开发环境）
    key = (timestamp + nonce + token).encode("utf-8") + body
    sig = hashlib.sha256(key).hexdigest()
    incoming = request.headers.get("X-Lark-Signature", "")
    return hmac.compare_digest(sig, incoming)


# ════════════════════════════════════════════════════════════
# 飞书 API 工具函数
# ════════════════════════════════════════════════════════════

def get_tenant_token() -> str:
    """获取 tenant_access_token，带缓存、锁和重试。
    失败时清空缓存防止中毒，指数退避重试 3 次。"""
    with _token_lock:
        if time.time() < _token_cache["expire"] - 120:
            return _token_cache["token"]
        last_err = None
        for attempt in range(3):
            try:
                resp = requests.post(
                    f"{FEISHU_API}/auth/v3/tenant_access_token/internal",
                    json={"app_id": FEISHU_CONFIG["app_id"],
                          "app_secret": FEISHU_CONFIG["app_secret"]},
                    timeout=10,
                )
                data = resp.json()
                if data.get("code") != 0:
                    raise RuntimeError(f"飞书Token获取失败: {data.get('msg')}")
                _token_cache["token"] = data["tenant_access_token"]
                _token_cache["expire"] = time.time() + data.get("expire", 7200)
                return _token_cache["token"]
            except Exception as e:
                last_err = e
                _token_cache["token"] = ""
                _token_cache["expire"] = 0
                logger.warning("tenant_token 获取失败 (attempt %d/3): %s", attempt + 1, e)
                if attempt < 2:
                    time.sleep(1 * (attempt + 1))
        raise RuntimeError(f"飞书Token获取失败（3次重试后放弃）: {last_err}")


def _post(path: str, payload: dict) -> dict:
    """通用飞书 API POST，带返回值校验"""
    token = get_tenant_token()
    r = requests.post(
        f"{FEISHU_API}{path}",
        headers={"Authorization": f"Bearer {token}",
                 "Content-Type": "application/json"},
        json=payload,
        timeout=20,
    )
    data = r.json()
    code = data.get("code", -1)
    if code != 0:
        logger.warning("飞书 API %s 返回错误 code=%s msg=%s", path, code, data.get("msg"))
    return data


def send_text(chat_id: str, text: str) -> bool:
    """向群/会话发送纯文本消息，返回是否成功"""
    try:
        data = _post("/im/v1/messages?receive_id_type=chat_id", {
            "receive_id": chat_id,
            "msg_type":   "text",
            "content":    json.dumps({"text": text}),
        })
        return data.get("code") == 0
    except Exception as e:
        logger.error("send_text 失败: %s", e)
        return False


def send_card(chat_id: str, card: dict) -> bool:
    """向群/会话发送卡片消息，返回是否成功"""
    try:
        data = _post("/im/v1/messages?receive_id_type=chat_id", {
            "receive_id": chat_id,
            "msg_type":   "interactive",
            "content":    json.dumps(card),
        })
        return data.get("code") == 0
    except Exception as e:
        logger.error("send_card 失败: %s", e)
        return False


# ════════════════════════════════════════════════════════════
# 卡片构建
# ════════════════════════════════════════════════════════════

def _build_brief_card(brief_text: str, source_info: dict) -> dict:
    """将要讯正文 + 来源信息组装成飞书互动卡片"""
    title  = (source_info.get("title") or "防务要讯")[:60]
    source = source_info.get("source", "")
    url    = source_info.get("url", "")
    now    = time.localtime()
    ts     = f"{now.tm_mon:02d}月{now.tm_mday:02d}日 {now.tm_hour:02d}:{now.tm_min:02d}"

    # 飞书卡片单元素内容限 5000 字符，分段展示
    preview = brief_text[:1500] + ("…" if len(brief_text) > 1500 else "")

    elements = [
        {"tag": "div", "text": {"tag": "lark_md",
            "content": f"**📰 素材标题**　{title}"}},
        {"tag": "div", "text": {"tag": "lark_md",
            "content": f"**📍 信源**　{source or '用户导入'}　　**🕐**　{ts}"}},
        {"tag": "hr"},
        {"tag": "div", "text": {"tag": "lark_md",
            "content": f"**📋 要讯全文**\n\n{preview}"}},
    ]

    if url:
        elements.append({
            "tag": "action",
            "actions": [{
                "tag":  "button",
                "text": {"tag": "plain_text", "content": "🔗 查看原文"},
                "type": "default",
                "url":  url,
            }]
        })

    return {
        "config": {"wide_screen_mode": True},
        "header": {
            "title":    {"tag": "plain_text", "content": "🛡️ 防务要讯已生成"},
            "template": "blue",
        },
        "elements": elements,
    }


def _build_error_card(msg: str) -> dict:
    """错误提示卡片"""
    return {
        "config": {"wide_screen_mode": True},
        "header": {
            "title":    {"tag": "plain_text", "content": "❌ 生成失败"},
            "template": "red",
        },
        "elements": [
            {"tag": "div", "text": {"tag": "lark_md", "content": msg}},
            {"tag": "div", "text": {"tag": "lark_md",
                "content": "**提示**：检查链接是否可访问，或AI Key是否已在系统中配置"}},
        ],
    }


# ════════════════════════════════════════════════════════════
# DOCX 要讯排版（严格按模板1格式）
# ════════════════════════════════════════════════════════════

def _set_font(run, font_name: str, size_pt: float = 16, bold: bool = True):
    """设置 run 的中西文字体"""
    run.font.name = font_name
    run.font.size = Pt(size_pt)
    run.font.bold = bold
    rPr = run._element.get_or_add_rPr()
    rFonts = rPr.get_or_add_rFonts()
    rFonts.set(qn('w:eastAsia'), font_name)


def _add_para(doc, align=None, left_indent=None, first_indent=None):
    """添加段落并设置统一行距 + 缩进"""
    p = doc.add_paragraph()
    pf = p.paragraph_format
    pf.line_spacing_rule = WD_LINE_SPACING.EXACTLY
    pf.line_spacing = Emu(363220)    # 固定行距 28.6pt
    pf.space_before = Pt(0)
    pf.space_after = Pt(0)
    if align is not None:
        p.alignment = align
    if left_indent is not None:
        pf.left_indent = Emu(left_indent)
    if first_indent is not None:
        pf.first_line_indent = Emu(first_indent)
    return p


def _parse_brief_sections(text: str) -> dict:
    """解析 AI 输出为六部分结构，带健壮的 fallback。
    即使 AI 输出格式不规范（缺少标签行、段落混乱），也能尽量提取可用内容。"""
    lines = text.strip().split('\n')
    sec = {'event_time': '', 'value_point': '', 'title': '',
           'body': '', 'source': '', 'reporter': '报送人：           电话：'}

    remaining = []
    for line in lines:
        s = line.strip()
        if not s:
            continue
        if s.startswith('事件时间'):
            sec['event_time'] = s
        elif '价' in s and '值' in s and '点' in s and '：' in s:
            sec['value_point'] = s
        elif s.startswith('（信息来源') or s.startswith('(信息来源'):
            sec['source'] = s
        elif s.startswith('报送人'):
            sec['reporter'] = s
        else:
            remaining.append(s)

    non_empty = [l for l in remaining if l]
    if non_empty:
        longest_idx = max(range(len(non_empty)), key=lambda i: len(non_empty[i]))
        sec['body'] = non_empty[longest_idx]
        title_parts = [non_empty[i] for i in range(len(non_empty)) if i != longest_idx]
        sec['title'] = ''.join(title_parts)

    # ── Fallback 兜底 ──
    if not sec['event_time']:
        now = time.localtime()
        sec['event_time'] = f"事件时间：{now.tm_year:04d}年{now.tm_mon:02d}月{now.tm_mday:02d}日"
        logger.warning("AI 输出缺少'事件时间'行，已自动填充今日日期")
    if not sec['title'] and sec['body']:
        sec['title'] = sec['body'][:20].rstrip('，。、；') + "值得关注"
        logger.warning("AI 输出缺少标题，已从正文截取")
    if not sec['body']:
        sec['body'] = text.strip()[:500]
        logger.warning("AI 输出无法解析正文段落，已将全文作为正文")
    if not sec['source']:
        logger.warning("AI 输出缺少'信息来源'行")
    return sec


def _generate_brief_docx(brief_text: str) -> bytes:
    """将要讯纯文本生成为严格排版的 .docx（按模板1格式）"""
    sec = _parse_brief_sections(brief_text)
    doc = DocxDocument()

    # ── 页面设置：A4 ──
    section = doc.sections[0]
    section.page_width  = Emu(7560310)     # A4 宽
    section.page_height = Emu(10692130)    # A4 高
    section.top_margin    = Emu(914400)    # 上 2.54cm
    section.bottom_margin = Emu(914400)    # 下 2.54cm
    section.left_margin   = Emu(1143000)   # 左 3.18cm
    section.right_margin  = Emu(1143000)   # 右 3.18cm

    # ── P0: 事件时间 ──
    # "事件时间：" 黑体 + 日期 楷体_GB2312
    p = _add_para(doc)
    et = sec['event_time']
    if '：' in et:
        label, date_val = et.split('：', 1)
        r1 = p.add_run(label + '：')
        _set_font(r1, '黑体')
        r2 = p.add_run(date_val)
        _set_font(r2, '楷体_GB2312')
    else:
        r = p.add_run(et)
        _set_font(r, '黑体')

    # ── P1: 价值点 ──
    # "价 值 点：" 黑体 + 内容 楷体_GB2312，悬挂缩进
    p = _add_para(doc, left_indent=1019810, first_indent=-1019810)
    vp = sec['value_point']
    if '：' in vp:
        label, content = vp.split('：', 1)
        r1 = p.add_run(label + '：')
        _set_font(r1, '黑体')
        r2 = p.add_run(content)
        _set_font(r2, '楷体_GB2312')
    else:
        r = p.add_run(vp)
        _set_font(r, '黑体')

    # ── P2: 空行（标题前） ──
    _add_para(doc, align=WD_ALIGN_PARAGRAPH.CENTER,
              left_indent=1606550, first_indent=-1612900)

    # ── P3: 标题 ──
    # 方正小标宋简体 22pt 居中
    p = _add_para(doc, align=WD_ALIGN_PARAGRAPH.CENTER,
                  left_indent=1606550, first_indent=-1612900)
    r = p.add_run(sec['title'])
    _set_font(r, '方正小标宋简体', 22)

    # ── P4: 空行（标题后） ──
    p = _add_para(doc, align=WD_ALIGN_PARAGRAPH.CENTER,
                  left_indent=1606550, first_indent=-1612900)
    r = p.add_run('      ')
    _set_font(r, '方正小标宋简体', 22)

    # ── P5: 正文 ──
    # 仿宋_GB2312 16pt 首行缩进2字符
    p = _add_para(doc, first_indent=408305)
    r = p.add_run(sec['body'])
    _set_font(r, '仿宋_GB2312')

    # ── P6: 信息来源 ──
    if sec['source']:
        p = _add_para(doc, first_indent=408305)
        r = p.add_run(sec['source'])
        _set_font(r, '楷体_GB2312')

    # ── P7: 报送人 ──
    p = _add_para(doc, align=WD_ALIGN_PARAGRAPH.CENTER)
    r = p.add_run(sec['reporter'])
    _set_font(r, '楷体_GB2312')

    buf = BytesIO()
    doc.save(buf)
    return buf.getvalue()


# ════════════════════════════════════════════════════════════
# 飞书文件上传 + 发送
# ════════════════════════════════════════════════════════════

def upload_file(file_name: str, file_data: bytes, file_type: str = "stream") -> str:
    """上传文件到飞书，返回 file_key。失败时用 ASCII fallback 重试。"""
    token = get_tenant_token()
    cleaned_name = _sanitize_feishu_filename(file_name)
    lower = cleaned_name.lower()
    ext_map = {
        ".docx": ("doc", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
        ".doc":  ("doc", "application/msword"),
        ".xlsx": ("xls", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        ".xls":  ("xls", "application/vnd.ms-excel"),
        ".pptx": ("ppt", "application/vnd.openxmlformats-officedocument.presentationml.presentation"),
        ".ppt":  ("ppt", "application/vnd.ms-powerpoint"),
        ".pdf":  ("pdf", "application/pdf"),
        ".txt":  ("stream", "text/plain"),
        ".md":   ("stream", "text/markdown"),
    }
    mime = "application/octet-stream"
    matched_ext = ".bin"
    for ext, (ft, mt) in ext_map.items():
        if lower.endswith(ext):
            file_type = ft
            mime = mt
            matched_ext = ext
            break
    ascii_placeholder = f"upload{matched_ext}"

    def _do_upload(send_name: str) -> dict:
        resp = requests.post(
            f"{FEISHU_API}/im/v1/files",
            headers={"Authorization": f"Bearer {token}"},
            data={"file_type": file_type, "file_name": send_name},
            files={"file": (ascii_placeholder, file_data, mime)},
            timeout=30,
        )
        return resp.json()

    data = _do_upload(cleaned_name)
    last_err = data.get("msg", "")
    if data.get("code") == 0:
        return data["data"]["file_key"]

    logger.warning("飞书上传第一次失败 (%s)，尝试 ASCII fallback", last_err)
    fallback_name = _ascii_fallback_name(matched_ext, original=file_name)
    data = _do_upload(fallback_name)
    if data.get("code") == 0:
        logger.info("飞书上传 ASCII fallback 成功: %s", fallback_name)
        return data["data"]["file_key"]

    raise RuntimeError(
        f"飞书文件上传失败: {data.get('msg', last_err)} "
        f"(file_type={file_type}, size={len(file_data)}B, "
        f"tried_name={cleaned_name!r}, fallback={fallback_name!r})"
    )


def send_file(chat_id: str, file_key: str):
    """向群/会话发送文件消息"""
    _post("/im/v1/messages?receive_id_type=chat_id", {
        "receive_id": chat_id,
        "msg_type":   "file",
        "content":    json.dumps({"file_key": file_key}),
    })


# ════════════════════════════════════════════════════════════
# 消息处理逻辑
# ════════════════════════════════════════════════════════════

def _extract_url(text: str) -> str | None:
    """从文本中提取第一个 HTTP URL"""
    m = re.search(r'https?://[^\s<>"{}|\\^`\[\]]+', text)
    return m.group(0) if m else None


def _process_async(chat_id: str, text: str):
    """在子线程中处理消息，生成并回复要讯（避免飞书 3s 超时）"""
    try:
        from app import (
            _extract_url_content,
            _build_brief_user_prompt_imported,
            _call_ai,
            _validate_brief_text,
            SYSTEM_PROMPT_BRIEF_WRITE,
            AI_CONFIG,
        )

        if not AI_CONFIG.get("api_key"):
            send_text(chat_id,
                "❌ AI API Key 未配置。\n"
                "请先在电脑端追踪系统的「🤖 AI分析 → ⚙️ 配置AI」中设置 Key。")
            return

        url = _extract_url(text)

        if url:
            # ── URL 模式 ──────────────────────────────────
            # SSRF 防护：禁止访问私有/本地地址
            from app import _is_ssrf_safe
            safe, reason = _is_ssrf_safe(url)
            if not safe:
                send_text(chat_id, f"❌ URL不安全，拒绝访问：{reason}")
                return
            send_text(chat_id, f"⏳ 正在抓取链接，请稍候（约10-30秒）…")
            extracted = _extract_url_content(url)
            body = extracted.get("body", "")
            if not body or len(body) < 50:
                send_card(chat_id, _build_error_card(
                    f"无法提取页面正文（字符数：{len(body)}）\n链接：{url}"))
                return
            source_info = {
                "title":  extracted.get("title", url[:60]),
                "source": extracted.get("source", ""),
                "url":    url,
            }
            prompt = _build_brief_user_prompt_imported(
                title=extracted.get("title", ""),
                body=body,
                source=extracted.get("source", ""),
                url=url,
                pub_date=extracted.get("pub_date", ""),
            )

        elif len(text) >= 30:
            # ── 纯文本模式 ────────────────────────────────
            send_text(chat_id, "⏳ 正在根据文本内容生成要讯，请稍候…")
            source_info = {"title": text[:40], "source": "用户导入", "url": ""}
            prompt = _build_brief_user_prompt_imported(
                title=text[:40], body=text,
                source="用户导入", url="", pub_date="")

        else:
            send_text(chat_id,
                "💡 请发送以下任一内容：\n"
                "① 文章链接（自动抓取正文）\n"
                "② 文章正文（30字以上）\n\n"
                "发送「帮助」查看使用说明")
            return

        # ── 调用 AI ───────────────────────────────────────
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT_BRIEF_WRITE},
            {"role": "user",   "content": prompt},
        ]
        result = _call_ai(messages, temperature=0.4)

        # ── 回复卡片预览 ─────────────────────────────────
        send_card(chat_id, _build_brief_card(result, source_info))

        # ── 生成 DOCX 并发送文件 ─────────────────────────
        try:
            docx_bytes = _generate_brief_docx(result)
            title_short = (source_info.get("title") or "防务要讯")[:30]
            ts = time.strftime("%Y%m%d_%H%M")
            file_name = f"要讯_{title_short}_{ts}.docx"
            file_key = upload_file(file_name, docx_bytes)
            send_file(chat_id, file_key)
        except Exception as docx_err:
            logger.error("DOCX生成/发送失败: %s", docx_err, exc_info=True)
            send_text(chat_id, f"⚠️ 要讯文本已生成，但DOCX文件发送失败：{str(docx_err)[:100]}")

    except Exception as e:
        logger.error("feishu_bot process error: %s", e, exc_info=True)
        send_card(chat_id, _build_error_card(f"处理异常：{str(e)[:120]}"))


# ════════════════════════════════════════════════════════════
# Flask 路由
# ════════════════════════════════════════════════════════════

HELP_TEXT = (
    "🛡️ **防务要讯机器人** 使用说明\n\n"
    "📌 **支持的消息类型**\n"
    "• 发送文章链接 → 自动抓取正文并生成要讯\n"
    "• 发送文章正文（30字+）→ 直接生成要讯\n\n"
    "📝 **示例**\n"
    "```\nhttps://www.scmp.com/news/military/...\n```\n\n"
    "⏱️ 生成约需 10-30 秒，生成中会先收到「⏳」提示。"
)


@feishu_bp.route("/api/feishu/webhook", methods=["POST"])
def feishu_webhook():
    """飞书事件订阅回调入口（需在飞书开放平台注册为事件订阅URL）"""
    raw_body = request.get_data()
    data = request.get_json(silent=True) or {}

    # ── URL 验证（首次注册 webhook 时飞书发来）──────────────
    if data.get("type") == "url_verification":
        challenge = data.get("challenge", "")
        logger.info("feishu_bot: URL verification OK")
        return jsonify({"challenge": challenge})

    # ── 签名校验（防伪造事件）────────────────────────────────
    ts    = request.headers.get("X-Lark-Request-Timestamp", "")
    nonce = request.headers.get("X-Lark-Request-Nonce", "")
    verify_token = FEISHU_CONFIG.get("verify_token", "")
    if verify_token and not _verify_feishu_signature(verify_token, ts, nonce, raw_body):
        logger.warning("feishu_bot: 签名校验失败，请求被拒绝")
        return jsonify({"code": 1, "msg": "invalid signature"}), 403

    # ── 事件处理（schema 2.0）────────────────────────────────
    header     = data.get("header", {})
    event_type = header.get("event_type", "")
    event      = data.get("event", {})

    if event_type != "im.message.receive_v1":
        return jsonify({"code": 0})

    message  = event.get("message", {})
    msg_type = message.get("message_type", "")
    chat_id  = message.get("chat_id", "")
    msg_id   = message.get("message_id", "")

    if not chat_id:
        return jsonify({"code": 0})

    # ── 去重：防飞书重试导致重复处理 ─────────────────────────
    if not _is_new_message(msg_id):
        logger.info("feishu_bot: 重复消息 %s，跳过", msg_id)
        return jsonify({"code": 0})

    # 只处理文本消息
    if msg_type != "text":
        send_text(chat_id,
            "💡 目前支持文字消息（链接 或 正文）。\n发送「帮助」查看使用说明。")
        return jsonify({"code": 0})

    try:
        text = json.loads(message.get("content", "{}")).get("text", "").strip()
    except Exception:
        return jsonify({"code": 0})

    if not text:
        return jsonify({"code": 0})

    # 帮助指令
    if text in ["帮助", "help", "?", "？", "/help"]:
        send_text(chat_id, HELP_TEXT)
        return jsonify({"code": 0})

    # 异步线程池生成（立即返回 200，避免飞书重试）
    _worker_pool.submit(_process_async, chat_id, text)

    return jsonify({"code": 0})


@feishu_bp.route("/api/feishu/config", methods=["GET", "POST"])
def feishu_config():
    """读写飞书机器人配置（供前端设置页调用，需登录）"""
    from app import require_auth as _require_auth
    # 手动调用认证检查（Blueprint 内无法直接用装饰器引用 app 的 require_auth）
    token = (request.cookies.get("access_token") or
             request.headers.get("X-Access-Token", ""))
    import secrets as _sec
    from app import ACCESS_TOKEN as _AT, validate_csrf_request, csrf_error_response
    if not token or not _sec.compare_digest(token, _AT):
        return jsonify({"error": "未授权"}), 401
    if request.method == "POST":
        if not validate_csrf_request():
            return csrf_error_response()
        data = request.get_json() or {}
        if data.get("app_id"):
            FEISHU_CONFIG["app_id"] = data["app_id"]
        if data.get("app_secret"):
            FEISHU_CONFIG["app_secret"] = data["app_secret"]
        if data.get("verify_token"):
            FEISHU_CONFIG["verify_token"] = data["verify_token"]
        # 清除 token 缓存，让下次请求重新获取
        with _token_lock:
            _token_cache["expire"] = 0
        _save_feishu_config()
        return jsonify({"ok": True,
                        "app_id": FEISHU_CONFIG["app_id"],
                        "configured": bool(FEISHU_CONFIG["app_id"])})
    return jsonify({
        "app_id":     FEISHU_CONFIG["app_id"],
        "configured": bool(FEISHU_CONFIG["app_id"] and FEISHU_CONFIG["app_secret"]),
        "webhook_url": "/api/feishu/webhook  （需配合 ngrok 或公网域名使用）",
    })


@feishu_bp.route("/api/feishu/test", methods=["POST"])
def feishu_test():
    """向指定 chat_id 发送一条测试消息，验证机器人配置是否正确（需登录）"""
    import secrets as _sec
    from app import ACCESS_TOKEN as _AT, validate_csrf_request, csrf_error_response
    token = (request.cookies.get("access_token") or
             request.headers.get("X-Access-Token", ""))
    if not token or not _sec.compare_digest(token, _AT):
        return jsonify({"error": "未授权"}), 401
    if not validate_csrf_request():
        return csrf_error_response()
    data = request.get_json() or {}
    chat_id = data.get("chat_id", "")
    if not chat_id:
        return jsonify({"error": "需要 chat_id"}), 400
    try:
        send_text(chat_id, "✅ 防务要讯机器人连接正常！发送文章链接即可生成要讯。")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
