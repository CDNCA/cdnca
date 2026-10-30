# Web 发布流程

## 原则

- 服务器禁止 `git pull` 后现场构建。服务器只接收已经在本地验证过的不可变制品。
- `web-dist*.tar.gz` 等手工命名的临时包禁止继续使用，避免拿错旧包覆盖新修复。
- 每个发布包都绑定一个 Git commit、Git tree、文件清单和 SHA-256 manifest。后续修改必须从包含前一轮修改的新 commit 重新生成包。
- 工作区有其他未提交改动时，发布脚本只读取指定 commit，不会把脏改动混进制品，也不会修改或清理这些改动。

## 生成制品

在仓库根目录执行。`VITE_TURNSTILE_SITE_KEY` 是公开构建参数，不要把其他密钥放进构建环境或命令行。

```bash
VITE_TURNSTILE_SITE_KEY='本次构建使用的公开 site key' \
  pnpm web:release \
  --source-ref HEAD \
  --output-dir /tmp/cdnca-web-releases
```

如果线上已经有上一版 `static/web.release.manifest.json`，必须追加 `--previous-manifest /path/to/current/static/web.release.manifest.json`。脚本会用 Git ancestry 拒绝不是上一版后代的旧分支；首次发布没有上一版时才省略此参数。

如果已经从当前线上全部 JavaScript 制品和运行环境确认 `VITE_TURNSTILE_SITE_KEY` 原本就是空值，可在本次兼容发布中显式使用 `--allow-empty-turnstile-site-key` 保持现有行为。默认仍拒绝空值；不得为了让构建通过而填入测试 key 或猜测生产 key。

生产 Web 发布必须保持 `VITE_PACKAGE_COMMERCE_ENABLED=true`。未设置该变量时前端默认开启；显式设置为 `false` 只允许用于受控测试或开发降级，Vite、Docker 构建、release 打包和 manifest 校验都会拒绝将其带入生产制品。

脚本会从 `--source-ref` 的 commit 归档出干净源码，执行 frozen install 和 Web production build，然后生成两个必须成对传输的文件：

```text
/tmp/cdnca-web-releases/web-<commit>.tar.gz
/tmp/cdnca-web-releases/web-<commit>.manifest.json
```

发布前必须保留脚本输出中的 `source_commit`、`source_tree` 和 `archive_sha256`。不要重新打包、改名或覆盖同一个 release ID。

## 上传和切换

以下示例使用管理 Web 的不可变 release 目录。实际主机、健康 URL 和服务名以当前运维清单为准。

1. 只上传同一个 `<commit>` 的 `.tar.gz` 与 `.manifest.json`。
2. 记录旧的 `current` 目标，将这个完整不可变 release 复制到全新的 release 目录，保留其中的 `bin/`、配置和其他静态资源。
3. 只清空并替换新 release 中的 `static/web`；不要解压到 `current`，不要修改旧 release。
4. 用 manifest 校验来源 commit、文件数量和 `static/web` 中每个文件的 SHA-256。
5. 先创建新 `current` 临时软链接，再原子替换 `current`，并把旧目标写入 `previous`。
6. 重启 Web 服务并检查 readiness、入口文件和本次 manifest 中的关键资源。
7. 验证失败时只把 `current` 原子切回 `previous`，保留失败 release 供审计，不删除回滚目录。

示意命令：

```bash
release_id='完整版本号-web-<commit>'
release_root="/data/cdnca/releases/$release_id"
old_current="$(readlink -f /data/cdnca/current)"
web_archive="/path/to/web-<commit>.tar.gz"
web_manifest="/path/to/web-<commit>.manifest.json"

test -d "$old_current"
test ! -e "$release_root"
install -d -m 0755 "$release_root"
cp -a "$old_current/." "$release_root/"
rm -rf "$release_root/static/web"
install -d -m 0755 "$release_root/static/web"
tar -xzf "$web_archive" -C "$release_root/static/web"
cp "$web_manifest" "$release_root/static/web.release.manifest.json"
verify_args=(
  --archive "$web_archive"
  --manifest "$release_root/static/web.release.manifest.json"
  --release-dir "$release_root/static/web"
)
if [ -f /data/cdnca/current/static/web.release.manifest.json ]; then
  verify_args+=(--current-manifest /data/cdnca/current/static/web.release.manifest.json)
fi
/path/to/cdnca/scripts/web-release-verify.sh \
  "${verify_args[@]}"

ln -s "$release_root" /data/cdnca/.current-next
mv -Tf /data/cdnca/.current-next /data/cdnca/current
ln -s "$old_current" /data/cdnca/.previous-next
mv -Tf /data/cdnca/.previous-next /data/cdnca/previous

systemctl restart cdnca-management-web.service
curl --fail --silent --show-error http://127.0.0.1/health/ready
test "$(readlink -f /data/cdnca/current)" = "$release_root"
test "$(readlink -f /data/cdnca/previous)" = "$old_current"
```

复制完成后必须确认新 release 的服务二进制仍然存在且平台正确，例如 `file "$release_root/bin/control-api"`。manifest 路径使用绝对路径；切换前还必须拒绝 `built_at` 不晚于当前 release 的制品，避免旧包再次覆盖新修复。真实发布脚本必须在切换前完成同样的校验，不能只依赖浏览器刷新后看起来正常。

## 明确禁止

```bash
git pull origin codex/release-gate-fixes
pnpm install
pnpm build
cp -r dist/* /var/www/html/
```

这组命令无法证明实际构建来源，也没有制品级回滚边界，正是“后一次发布把前一次修复带回去”的来源之一。
