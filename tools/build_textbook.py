#!/usr/bin/env python3
"""Copy osep-prep docs with minimal edits and inline referenced scripts."""
from __future__ import annotations

import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PREP = Path("/Users/barok/Desktop/Project/Certification/OSEP/osep-prep")
OUT = ROOT / "docs" / "modules"
PREP_DOCS = PREP / "docs"
PREP_SCRIPTS = PREP / "scripts"

HEADER = """::: warning 仅供授权实验与备考学习
本文是个人备考教材。源码只用于 OSEP 官方实验/考试环境，或你拥有书面授权的目标。禁止对未授权系统使用。
:::

"""

SCRIPT_RE = re.compile(r"scripts/[A-Za-z0-9_./-]+\.[A-Za-z0-9]+")
DOC_LINK_RE = re.compile(r"`?docs/([0-9]{2}-[a-z0-9-]+)\.md`?")
H2_RE = re.compile(r"(?=^## )", re.M)

LANG = {
    ".ps1": "powershell",
    ".cs": "csharp",
    ".c": "c",
    ".cpp": "cpp",
    ".py": "python",
    ".sh": "bash",
    ".vba": "vb",
    ".hta": "html",
    ".js": "javascript",
    ".aspx": "html",
    ".php": "php",
    ".jsp": "xml",
    ".sql": "sql",
    ".xsl": "xml",
    ".ics": "text",
    ".md": "markdown",
    ".conf": "nginx",
    ".xml": "xml",
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
        raw = m.group(0)
        if raw.startswith("`"):
            return f"[`docs/{name}.md`](/modules/{name})"
        return f"[docs/{name}.md](/modules/{name})"

    return DOC_LINK_RE.sub(repl, text)


def resolve_script(rel: str) -> Path | None:
    rel = rel.strip().lstrip("./")
    p = PREP / rel
    if p.is_file():
        return p
    return None


def expand_mentions(text: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for m in SCRIPT_RE.finditer(text):
        rel = m.group(0)
        if rel in seen:
            continue
        seen.add(rel)
        found.append(rel)
        # shorthand: `foo-x86.vba` / `-x64.vba`
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
        return f"\n> 源码未找到：`{rel}`\n"
    body = path.read_text(encoding="utf-8", errors="replace")
    slug = rel.replace("/", "-").replace(".", "-")
    return (
        f'\n#### 源码 `{rel}` {{#{slug}}}\n\n'
        + fence(lang_for(path), body)
    )


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
    # Prefer right after the 用到的脚本 table / heading
    marker = "**用到的脚本**"
    idx = section.find(marker)
    if idx == -1:
        idx = section.find("### 用到的脚本")
    if idx == -1:
        idx = section.find("## 用到的脚本")
    if idx != -1:
        rest = section[idx:]
        # end of table: blank line after last | row, then non-table
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
    # 文首保持原文；源码插在各 H2 节（场景）的「用到的脚本」表后
    out = [parts[0]]
    for part in parts[1:]:
        out.append(inject_section(part, already))
    body = "".join(out)
    leftover = [r for r in expand_mentions(raw) if resolve_script(r) and r not in already]
    if leftover:
        body += "\n## 其余引用脚本源码\n"
        for rel in leftover:
            body += render_script(rel)
    return HEADER + body


def copy_plain(src: Path, dest: Path, title_prefix: str | None = None) -> None:
    text = src.read_text(encoding="utf-8")
    text = rewrite_doc_links(text)
    dest.write_text(HEADER + text, encoding="utf-8")


def main() -> None:
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)

    for md in sorted(PREP_DOCS.glob("*.md")):
        dest = OUT / md.name
        dest.write_text(transform_doc(md), encoding="utf-8")
        print(f"wrote {dest.relative_to(ROOT)} ({dest.stat().st_size} bytes)")

    copy_plain(PREP / "scenarios.md", ROOT / "docs" / "scenarios.md")
    copy_plain(PREP / "CONVENTIONS.md", ROOT / "docs" / "conventions.md")
    copy_plain(PREP / "README.md", ROOT / "docs" / "prep-readme.md")
    copy_plain(PREP_SCRIPTS / "INDEX.md", ROOT / "docs" / "scripts-index.md")
    print("done")


if __name__ == "__main__":
    main()
