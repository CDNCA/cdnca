# @cdnca/site-theme-kit

官网主题插件（`cdnca.site-theme/v2`）开发工具，零依赖，Node.js 20 以上。完整说明在卖家中心“开发者文档 → 主题插件”（源文件 `apps/seller-portal/src/docs/content/zh-CN/site-theme-tools.md`）。

```sh
node packages/site-theme-kit/bin/cdnca-site-theme.mjs init my-theme --template user+site --plugin-id acme.dev.ocean
node packages/site-theme-kit/bin/cdnca-site-theme.mjs preview my-theme
node packages/site-theme-kit/bin/cdnca-site-theme.mjs preview my-theme --screenshot   # 生成 preview.webp
node packages/site-theme-kit/bin/cdnca-site-theme.mjs check my-theme
node packages/site-theme-kit/bin/cdnca-site-theme.mjs pack my-theme --sign --key publisher.key
```

- `lib/rules.mjs`：本地预检，规则与错误码同 `libs/sitetheme`（权威实现）。
- `lib/scaffold.mjs`：三种模板（`user+site`、`user`、`site`）。
- `lib/preview.mjs`：本地沙箱预览（CSP sandbox + 两个公开接口 mock）。
- `lib/pack.mjs`：打包 v2 content 与 manifest；签名调用 `cdnca-plugin sign-manifest`。根目录的 `preview.webp`（或 theme.config.json 的 `preview`）作为预览图打进 content，没有时只提示。
- `lib/screenshot.mjs`：`preview --screenshot` 用本机 Chrome 截 1440×900 首屏，生成 `preview.webp`（有 cwebp）或 `preview.png`。

测试：`node --test packages/site-theme-kit/test/*.test.mjs`
