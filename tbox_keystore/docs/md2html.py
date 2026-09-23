#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
md → A4 打印版 HTML 生成器（tbox_keystore 文档系列统一版式）

用法:
    python3 md2html.py <input.md> [-o <output.html>]
                        [--title T] [--sub S] [--audience A]

版式与 docs/21、22、33 完全一致（同一套 CSS）：
  · A4 / 紧凑打印排版 / 仅"第X部分"级标题分页
  · ASCII 框图自动加 class="ascii-diagram"（white-space:pre 不折行）
  · 封面 + 自动目录 + 页脚

注意：本生成器是 2026-09 补写的——原先的生成脚本已丢失，
docs/33 的 HTML 是手工补丁维护的。用本脚本重新生成时请 diff 确认。
"""
import argparse, datetime, os, re, sys

try:
    import markdown
except ImportError:
    sys.exit("需要 python3-markdown：apt install python3-markdown")

CSS = """  @page { size: A4; margin: 13mm 12mm 13mm 12mm; }
  @media screen { body { max-width:185mm; margin:0 auto; padding:24px 0;
                         font-size:10.5pt; line-height:1.7; } }
  @media print {
    body { -webkit-print-color-adjust:exact; print-color-adjust:exact;
           font-size:9.1pt; line-height:1.4; orphans:2; widows:2; }
    h1.part { page-break-before: always; }
    h1, h2, h3, h4 { page-break-after: avoid; }
    .no-print { display:none; }
    p { margin:3px 0; }
    h1 { font-size:14pt;  margin:10px 0 6px 0; padding-bottom:3px; }
    h2 { font-size:12pt;  margin:10px 0 4px 0; padding-bottom:2px; }
    h3 { font-size:10.4pt; margin:7px 0 3px 0; }
    h4 { font-size:9.6pt; margin:5px 0 2px 0; }
    table { margin:4px 0 7px 0; font-size:8.4pt; }
    th, td { padding:2.5px 4px; }
    pre { margin:4px 0 7px 0; padding:5px 8px; font-size:7.7pt; line-height:1.28; }
    pre.ascii-diagram { font-size:7.3pt; line-height:1.18; }
    blockquote { margin:5px 0; padding:5px 9px; font-size:8.9pt; }
    blockquote p { margin:3px 0; }
    blockquote pre { margin:3px 0 5px 0; }
    blockquote table { font-size:8.1pt; }
    ul, ol { margin:2px 0 6px 0; padding-left:18px; }
    li { margin:1px 0; }
    hr { margin:8px 0; }
    .cover { padding:40mm 0 0 0; }
    .toc { font-size:9.6pt; }
    .toc > ul > li { margin:3px 0; }
    .toc ul ul li { margin:1px 0; font-size:9pt; }
    .footer { margin-top:14px; padding-top:6px; }
  }
  body { font-family:"Noto Sans SC","Source Han Sans CN","Microsoft YaHei","SimSun",sans-serif;
         color:#1a1a1a; }
  .cover { text-align:center; }
  .cover h1 { font-size:25pt; font-weight:700; margin:0 0 10px 0; letter-spacing:2px;
              border:none; padding:0; }
  .cover .sub { font-size:12pt; color:#555; margin-bottom:34px; }
  .cover .divider { width:58%; height:1px; background:#1a1a1a; margin:22px auto; }
  .cover .meta { font-size:10pt; color:#777; }
  .cover .meta p { margin:3px 0; }
  h1 { font-size:18pt; font-weight:700; padding-bottom:5px; border-bottom:2px solid #1a1a1a; }
  h2 { font-size:15pt; font-weight:700; padding-bottom:4px; border-bottom:1.5px solid #1a1a1a; }
  h3 { font-size:12.5pt; font-weight:600; }
  h4 { font-size:11pt; font-weight:600; }
  table { width:100%; border-collapse:collapse; }
  th { background:#1a1a1a; color:#fff; text-align:left; font-weight:600; }
  td { border-bottom:1px solid #ccc; vertical-align:top; }
  tr:nth-child(even) td { background:#f7f7f7; }
  code { font-family:"JetBrains Mono","Consolas","Courier New",monospace; font-size:0.92em;
         background:#f0f0f0; padding:1px 4px; border-radius:2px; }
  pre { background:#f4f4f4; border:1px solid #ddd; border-left:3px solid #1a1a1a; overflow-x:auto; }
  pre code { background:none; padding:0; }
  pre.ascii-diagram { white-space: pre; }
  blockquote { background:#fffbe6; border-left:4px solid #d4a017; }
  blockquote h2, blockquote h3, blockquote h4 { border:none; padding:0; margin:6px 0 4px 0;
               font-size:1.05em; }
  blockquote pre { background:#fff8d8; }
  hr { border:none; border-top:1px solid #ddd; }
  .toc ul { list-style:none; padding-left:0; margin:0; }
  .toc > ul > li { font-weight:600; }
  .toc ul ul { padding-left:20px; }
  .toc ul ul li { font-weight:400; }
  .toc a { color:#1a1a1a; text-decoration:none; }
  .footer { text-align:center; font-size:9pt; color:#999; border-top:1px solid #ccc; }
  /* Mermaid 图：屏幕居中，打印时尽量不跨页断开 */
  .mermaid { text-align:center; margin:10px 0; }
  .mermaid svg { max-width:100%; height:auto; }
  @media print { .mermaid { page-break-inside:avoid; } .mermaid svg { max-height:215mm; } }
"""

BOXCHARS = "┌┐└┘├┤┬┴┼─│▼▲◀▶═"


def build(md_path, title=None, sub=None, audience=None):
    src = open(md_path, encoding="utf-8").read()
    name = os.path.basename(md_path)

    # 标题：优先命令行，其次 MD 的第一个 H1
    m = re.search(r"^#\s+(.+)$", src, re.M)
    if not title:
        title = re.sub(r"^\d+\s*[—-]\s*", "", m.group(1)).strip() if m else name

    md = markdown.Markdown(
        extensions=["toc", "tables", "fenced_code", "attr_list"],
        extension_configs={"toc": {"title": "", "toc_depth": "1-3"}},
    )
    # 文档自身的标题 H1 只用于封面/ <title>，正文与目录都不含它
    # （与 docs/33 的版式一致：目录从 H2 级开始，"第X部分"H1 仍在目录里）
    body_src = re.sub(r"^#\s+.+?\n", "", src, count=1, flags=re.M)
    body = md.convert(body_src)

    # 0) ```mermaid 围栏 → <pre class="mermaid">（交给 mermaid.js 在浏览器里渲染）
    def mermaid_block(mo):
        code = mo.group(1)
        return '<pre class="mermaid">' + code.strip() + "</pre>"
    body = re.sub(r'<pre><code class="language-mermaid">(.*?)</code></pre>',
                  mermaid_block, body, flags=re.S)

    # 1) "第X部分" 级 H1 加分页类
    body = re.sub(r"<h1(?!\s+class)([^>]*)>(第[一二三四五六七八九十]+部分)",
                  r'<h1 class="part"\1>\2', body)
    # 2) 含框线的 <pre> 加 ascii-diagram（保证 white-space:pre 不折行）
    def mark_ascii(mo):
        inner = mo.group(1)
        # 规则（与 docs/33 原版生成器一致）：
        #   无语言标签的围栏 —— 即「控制台输出样例 / ASCII 图」—— 一律加
        #   ascii-diagram（打印时 white-space:pre 不折行 + 小字号）。
        #   带语言标签的（bash/json/ini…）只有含框线字符时才加。
        labeled = inner.startswith('<code class="language-')
        if (not labeled) or any(c in inner for c in BOXCHARS):
            return '<pre class="ascii-diagram">' + inner + "</pre>"
        return mo.group(0)
    body = re.sub(r"<pre>(.*?)</pre>", mark_ascii, body, flags=re.S)

    # 目录：toc 扩展把结果放在 md.toc（不会自动进正文）
    toc_html = getattr(md, "toc", "") or ""

    today = datetime.date.today().isoformat()

    # Mermaid：优先用同目录下的本地文件（离线可用），否则回退 CDN
    if ".mermaid" in body or 'class="mermaid"' in body:
        here = os.path.dirname(os.path.abspath(md_path))
        local = os.path.join(here, "mermaid.min.js")
        if os.path.exists(local):
            # 单文件交付：把 mermaid.js 内联进来
            # 必须转义 '</script'，否则会提前闭合 <script> 标签
            js = open(local, encoding="utf-8").read().replace("</script", "<\\/script")
            mermaid_js = "<script>" + js + "</script>"
        else:
            mermaid_js = ('<script src="https://cdn.jsdelivr.net/npm/'
                          'mermaid@10/dist/mermaid.min.js"></script>')
            print("  ⚠️ 未找到 mermaid.min.js，已回退 CDN（离线打开将看不到图）")
        mermaid_js += ("\n<script>mermaid.initialize({startOnLoad:true,"
                       "theme:'neutral',securityLevel:'loose'});</script>")
    else:
        mermaid_js = ""
    cover_sub = sub or "TBox 安全服务系统 · 技术文档"
    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>{CSS}</style>
</head>
<body>
<div class="cover">
  <h1>{title}</h1>
  <div class="sub">{cover_sub}</div>
  <div class="divider"></div>
  <div class="meta">
    <p>面向对象：{audience or "项目相关工程师"}</p>
    <p>来源文件：docs/{name}</p>
    <p>生成日期：{today}</p>
  </div>
</div>
<div style="page-break-before:always;"></div>
<h1 style="border:none;">目录</h1>
{toc_html}
<div style="page-break-before:always;"></div>
{body}
<div class="footer">
  {title} · 由 docs/{name} 生成 · {today}
</div>
{mermaid_js}
</body>
</html>
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("md")
    ap.add_argument("-o", "--output")
    ap.add_argument("--title"); ap.add_argument("--sub"); ap.add_argument("--audience")
    a = ap.parse_args()
    out = a.output or re.sub(r"\.md$", ".html", a.md)
    open(out, "w", encoding="utf-8").write(build(a.md, a.title, a.sub, a.audience))
    print("生成:", out, os.path.getsize(out), "字节")


if __name__ == "__main__":
    main()
