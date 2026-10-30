// 文案涉及、但尚未合入当前版本的能力（www-design.md §0.1）。规则：页面只写已合入的
// 能力；未合入的置 false，相关文案整体不渲染（不写“交付中”）。合入后改成 true 即可上线文案。
export const AVAILABLE = {
  /** ADR 0015 直结 + 供货方自配收款通道、一键充值、回调记余额 */
  directPay: true,
  /** ADR 0015 §11 保证金 / 赔付 / 信用展示 */
  supplierDeposit: true,
  /** ADR 0016 迁移导入官方模块 module.migrate.import 与第三方导入适配器 */
  migrateImport: true,
} as const
