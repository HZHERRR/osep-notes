#!/usr/bin/env python3
"""Build cleaned Chinese textbook pages (no repo paths, no '源码' labels)."""
from __future__ import annotations

import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PREP = Path("/Users/barok/Desktop/Project/Certification/OSEP/osep-prep")
OUT = ROOT / "docs" / "zh" / "modules"
PREP_DOCS = PREP / "docs"

HEADER = """::: warning 仅限授权使用
本笔记仅用于 OSEP 官方实验 / 考试环境，或已获得书面授权的测试。禁止对未授权系统使用。
:::

"""

SCRIPT_RE = re.compile(r"scripts/[A-Za-z0-9_./-]+\.[A-Za-z0-9]+")
DOC_LINK_RE = re.compile(r"`?docs/([0-9]{2}-[a-z0-9-]+)\.md`?")
H2_RE = re.compile(r"(?=^## )", re.M)

LANG = {
    ".ps1": "powershell", ".cs": "csharp", ".c": "c", ".cpp": "cpp",
    ".py": "python", ".sh": "bash", ".vba": "vb", ".hta": "html",
    ".js": "javascript", ".aspx": "html", ".php": "php", ".jsp": "xml",
    ".sql": "sql", ".xsl": "xml", ".ics": "text", ".md": "markdown",
    ".conf": "nginx", ".xml": "xml",
}


def fence(lang: str, body: str) -> str:
    ticks = "````"
    while ticks in body:
        ticks += "`"
    return f"{ticks}{lang}\n{body.rstrip()}\n{ticks}\n"


def lang_for(path: Path) -> str:
    return LANG.get(path.suffix.lower(), "text")


def rewrite_doc_links(text: str) -> str:
    def repl(m: re.Match) -> str:
        name = m.group(1)
        return f"[{name}](/zh/modules/{name})"

    return DOC_LINK_RE.sub(repl, text)


def scrub(text: str) -> str:
    text = text.replace("osep-prep/", "").replace("osep-prep", "")
    text = re.sub(r"/Users/barok[^\s)`\]]*", "", text)
    text = re.sub(
        r"\[emmanuelsolis[^\]]*\]\([^)]+\)",
        "",
        text,
        flags=re.I,
    )
    text = re.sub(r"https?://www\.emmanuelsolis\.com[^\s)]*", "", text)
    text = re.sub(r"`reference/osep-cheatsheet\.md`", "", text)
    text = re.sub(r"reference/osep-cheatsheet\.md", "", text)
    text = re.sub(r"（本地副本：[^\)]*）", "", text)
    text = re.sub(r"cheat sheet 依据：[^\n]*\n", "", text)
    text = re.sub(r"> cheat sheet 依据：[^\n]*\n", "", text)
    text = re.sub(r"来源：`[^`]*`（用户整理的 OSEP 场景表）。\n", "", text)
    text = re.sub(r"`scripts/([^`]+)`", lambda m: f"`{Path(m.group(1)).name}`", text)
    text = re.sub(
        r"(?<![`\w])scripts/([A-Za-z0-9_./-]+\.[A-Za-z0-9]+)",
        lambda m: Path(m.group(1)).name,
        text,
    )
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text


def resolve_script(rel: str) -> Path | None:
    rel = rel.strip().lstrip("./")
    p = PREP / rel
    return p if p.is_file() else None


def expand_mentions(text: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for m in SCRIPT_RE.finditer(text):
        rel = m.group(0)
        if rel in seen:
            continue
        seen.add(rel)
        found.append(rel)
        if "-x86." in rel:
            alt = rel.replace("-x86.", "-x64.")
            if alt not in seen:
                seen.add(alt)
                found.append(alt)
        if "-x64." in rel:
            alt = rel.replace("-x64.", "-x86.")
            if alt not in seen and resolve_script(alt):
                seen.add(alt)
                found.append(alt)
    return found


def render_script(rel: str) -> str:
    path = resolve_script(rel)
    if not path:
        return ""
    body = path.read_text(encoding="utf-8", errors="replace")
    # VitePress generates the same stable slug from the filename. Kramdown-style
    # ``{#id}`` syntax is not supported here and would leak into accessibility
    # labels as literal text.
    return f"\n#### `{path.name}`\n\n" + fence(lang_for(path), body)


def inject_section(section: str, already: set[str]) -> str:
    mentions = expand_mentions(section)
    new = [r for r in mentions if resolve_script(r) and r not in already]
    if not new:
        return section
    blocks = []
    for rel in new:
        already.add(rel)
        blocks.append(render_script(rel))
    insert = "\n" + "".join(blocks)
    marker = "**用到的脚本**"
    idx = section.find(marker)
    if idx == -1:
        idx = section.find("### 用到的脚本")
    if idx != -1:
        rest = section[idx:]
        m = re.search(r"(?:\n\|[^\n]*)+\n", rest)
        if m:
            cut = idx + m.end()
            return section[:cut] + insert + section[cut:]
    return section.rstrip() + insert + "\n"


def transform_doc(src: Path) -> str:
    raw = src.read_text(encoding="utf-8")
    raw = rewrite_doc_links(raw)
    parts = H2_RE.split(raw)
    already: set[str] = set()
    out = [parts[0]]
    for part in parts[1:]:
        out.append(inject_section(part, already))
    body = "".join(out)
    leftover = [r for r in expand_mentions(src.read_text(encoding="utf-8")) if resolve_script(r) and r not in already]
    if leftover:
        body += "\n## 本页其余实验文件\n"
        for rel in leftover:
            body += render_script(rel)
    return HEADER + scrub(body)


def main() -> None:
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)

    for md in sorted(PREP_DOCS.glob("*.md")):
        dest = OUT / md.name
        dest.write_text(transform_doc(md), encoding="utf-8")
        print(f"wrote {dest.relative_to(ROOT)} ({dest.stat().st_size} bytes)")

    # scenarios → zh
    sc = (PREP / "scenarios.md").read_text(encoding="utf-8")
    sc = rewrite_doc_links(sc)
    sc = scrub(sc)
    (ROOT / "docs" / "zh" / "scenarios.md").write_text(HEADER + sc, encoding="utf-8")
    print("done")


if __name__ == "__main__":
    main()
