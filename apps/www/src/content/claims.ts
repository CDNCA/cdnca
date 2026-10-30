// 定价/收费口径的唯一文案来源（口径集中一处，便于一处修改）。
//
// 现状：官网宣传“主控免费，直接可用”，不做价格页，不展示
// 平台抽成。待确认：授权端种子套餐 vip1–vip5 目前按节点数收费
// （services/license-service/migrations/055_portal_license_plans.up.sql:54-59），
// 与“主控免费”不一致。口径定下后只改本文件；全站引用 FREE_CLAIM 的位置都会跟着变。
// 设为 null 时，首页徽标、FAQ“主控免费吗”与功能页相关文案整体不显示（测试覆盖）。
import type { Lang } from '../i18n'

export interface FreeClaim {
  /** 首页大字下方徽标、功能页标语 */
  badge: string
  /** 主 CTA 文字 */
  cta: string
  /** FAQ 问与答 */
  faqQ: string
  faqA: string
}

export const FREE_CLAIM: Record<Lang, FreeClaim> | null = {
  zh: {
    badge: '主控免费，直接可用',
    cta: '免费使用',
    faqQ: '主控真的免费吗？',
    faqA: '是。注册后在授权中心复制安装命令即可部署主控，直接可用。官方插件中标注“收费”的模块按插件市场的定价购买，不影响主控本身的使用。',
  },
  en: {
    badge: 'The control plane is free.',
    cta: 'Get started free',
    faqQ: 'Is the control plane really free?',
    faqA: 'Yes. Sign up, copy the install command from the licence centre and deploy. Modules marked “paid” in the plugin market are bought separately; the control plane itself stays usable.',
  },
}

/** 未定口径时主 CTA 的中性文字 */
export const NEUTRAL_CTA: Record<Lang, string> = { zh: '注册并开始', en: 'Sign up' }
