# OSEP 私人教材

**本仓库必须保持 private。** 不要改成 public，不要开公开的 GitHub Pages。

内容由 `osep-prep/docs` 原文生成，各场景「用到的脚本」后嵌了对应 `scripts/` 源码。

```bash
python3 tools/build_textbook.py   # 从 osep-prep 重新生成 docs/modules
npm install
npm run docs:dev                  # 仅本机 http://localhost:5173/
```

`osep-prep` 有更新时，先跑 `build_textbook.py` 再提交。
