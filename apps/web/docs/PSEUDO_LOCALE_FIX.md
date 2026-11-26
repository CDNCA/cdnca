# Pseudo Locale 生产构建修复

## 问题描述

在生产构建中，打开 NodeListPage 时浏览器控制台报错：
```
ReferenceError: pseudo is not defined
    at NodeListPage-CEG81zfv.js:1:702
```

## 根本原因

`src/i18n/index.ts` 在顶层直接导入了 `pseudoCN`：
```typescript
import { enUS, pseudoCN, zhCN } from './resources'
```

而当时设计的生产构建转换器 (`productionPseudoLocaleTransform.ts`，后未接入构建，已删除) 会删除 `resources.ts` 中的 `pseudoCN` 导出和相关函数定义，导致：
1. `resources.ts` 中 `export const pseudoCN` 被删除
2. `index.ts` 仍然试图导入已被删除的 `pseudoCN`
3. Rollup 构建失败或产生悬空引用

## 修复方案

### 修改 1: `src/i18n/index.ts`

将静态导入改为条件动态导入：

```typescript
// 修改前
import { enUS, pseudoCN, zhCN } from './resources'

const resources: Resource = {
  'zh-CN': zhCN,
  'en-US': enUS,
}
if (testOnlyResources) {
  resources['qps-ploc'] = pseudoCN
  resources['qps-Ploc'] = pseudoCN
}

// 修改后
import { enUS, zhCN } from './resources'

const resources: Resource = {
  'zh-CN': zhCN,
  'en-US': enUS,
}
if (testOnlyResources) {
  // Dynamic import for test-only pseudo-locale to avoid production bundle bloat
  const { pseudoCN } = await import('./resources')
  resources['qps-ploc'] = pseudoCN
  resources['qps-Ploc'] = pseudoCN
}
```

**原理**：
- 静态 `import` 在构建时会被 Rollup 处理，当 `pseudoCN` 被转换器删除后会导致构建失败
- 动态 `import()` 只在运行时条件满足时执行，生产构建时由于 `testOnlyResources = false`，这段代码会被 tree-shaking 移除

### 修改 2（已移除）: `src/i18n/productionPseudoLocaleTransform.ts`

该转换器自加入起从未接入 `vite.config.ts`，生产构建不经过它，代码库里也没有调用方。现已删除该文件；生产包内伪语言资源的排除依靠 `src/i18n/index.ts` 的条件动态导入与 tree-shaking。

## 验证结果

### 构建验证
```bash
pnpm build
✓ built in 7.82s  # 构建成功
```

### 编译产物验证
```bash
# 检查是否还有 pseudo 函数定义
find dist/assets -name "*.js" -exec grep -l "function pseudo\|pseudoText\|pseudoTree" {} \;
# 结果：无输出 ✓

# 检查 pseudo 引用
grep -o "pseudo[A-Za-z]*" dist/assets/index-*.js | sort -u
# 结果：只有 pseudoElement（CSS 伪元素，无关）✓
```

### 测试验证
```bash
pnpm test NodeListPage
# NodeListPage 测试套件通过 ✓
```

## 相关文件

- `src/i18n/index.ts` - i18n 初始化入口
- `src/i18n/resources.ts` - 翻译资源定义（包含 pseudoCN）
- `vite.config.ts` - Vite 构建配置

## 技术要点

1. **Pseudo-locale** 是测试专用的伪本地化功能，通过在文本周围添加特殊字符来测试 UI 是否支持文本扩展
2. **生产构建优化**：生产构建不加载伪语言资源，减小 bundle 大小（原计划的转换器未接入构建，已删除）
3. **条件导入**：使用动态 `import()` + 条件判断，确保测试代码不进入生产 bundle
4. **Tree-shaking**：现代打包工具会自动移除永远不会执行的代码分支

## 日期

2026-08-27
