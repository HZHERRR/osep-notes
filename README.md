# OSEP Notes

授权实验用的进攻性安全笔记站，用 [VitePress](https://vitepress.dev/) 生成，部署到 GitHub Pages。

本仓库**只放方法论、判断逻辑和公开工具的命令模板**。不含可执行 payload、webshell、AMSI 绕过实现、C2 客户端，也不含任何考试或实验靶场的逐步答案。

## 本地预览

```bash
npm install
npm run docs:dev
```

浏览器打开终端提示的地址（默认 `http://localhost:5173/osep-notes/`）。

构建：

```bash
npm run docs:build
npm run docs:preview
```

## 部署到 GitHub Pages

1. 新建公开仓库，名称建议与 `base` 一致：`osep-notes`。
2. 把本目录推上去：

   ```bash
   git init
   git add .
   git commit -m "Initial public notes"
   git branch -M main
   git remote add origin git@github.com:<你的用户名>/osep-notes.git
   git push -u origin main
   ```

3. 仓库 **Settings → Pages → Source** 选 **GitHub Actions**。
4. 若仓库名不是 `osep-notes`，同时改两处：
   - `docs/.vitepress/config.mts` 里的默认 `base`
   - `.github/workflows/deploy.yml` 里的 `VITEPRESS_BASE`

用户站（`https://<user>.github.io/`）把 `base` 和 `VITEPRESS_BASE` 都改成 `/`。

## 写了什么 / 没写什么

见站点内 [使用边界](docs/disclaimer.md)。
