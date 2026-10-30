# @cdnca/ui 页面组件

都从 `@cdnca/ui` 导入，样式在 `@cdnca/ui/styles.css`（各端根部已经引入）。tech 外观的样式也在这份文件里，作用域是 `html[data-cdnca-look="tech"]`。组件只管布局、尺寸和文案，数据和业务逻辑留在页面里。内置文案跟随最近一层 ConfigProvider 的 antd locale（zh-CN / zh-TW / en-US），默认中文。

## 页面骨架

```tsx
<PageHeader title="节点列表" description="管理全部边缘节点" extra={<Button icon={<RefreshCw size={14} />}>刷新</Button>} />
<PageSection>
  <TableToolbar
    actions={<><AddButton name="节点" onClick={openCreate} /><DangerButton confirmTitle={`确定删除选中的 ${n} 项？`} onConfirm={removeSelected} disabled={!n}>批量删除</DangerButton></>}
    filters={<><Select options={...} /><Input.Search placeholder="搜索名称" /></>}
  />
  <DataTable rowKey="id" columns={columns} dataSource={rows} />
</PageSection>
```

- `PageHeader`：`title` 必填，`description`、`extra` 可选。标题是 h1，18px/600，颜色 `--cdnca-color-title`；描述 13px；`extra` 和标题在同一行、靠右。每个页面都要有。
- `PageSection`：4px 圆角卡片（圆角走 `--cdnca-border-radius`），次级边框、阴影、16px 内边距，相邻区块间距 16px。可选 `title` / `extra` 做区块头。替代 `.identity-page` 和各页自定义的根容器。
- `TableToolbar`：`actions` 放左边（主操作、批量操作），`filters` 放右边（筛选、搜索）。直接子元素里的搜索框宽 240px、下拉框宽 150px（常量 `TOOLBAR_SEARCH_WIDTH` / `TOOLBAR_SELECT_WIDTH`），不要再写内联宽度。
- `DataTable`：antd Table，默认 `size="small"`、横向滚动、每页 20 条、分页靠右并显示「共 N 条」。传 `pagination` 就用你传的值；用游标分页时传 `pagination={false}`，再配合 `CursorPager`。
- `CursorPager`：`hasPrev`、`hasNext`、`onPrev`、`onNext` 必填，`total` 有值时显示「共 N 条」，`loading` 时两个按钮都禁用。替代各页自己画的上一页/下一页。

## 按钮

- `AddButton name="节点"`：primary 按钮加 Plus 图标，文案是「添加节点」。新增按钮一律用它，不再写新增/新建/创建。其余 ButtonProps 照常透传。
- `DangerButton`：default + danger 按钮，点击先弹二次确认（`confirmTitle` 必填，`confirmDescription`、`okText` 可选），确认后才调用 `onConfirm`。危险的批量操作和行内删除都用它，不要用 primary+danger。

## 弹窗与抽屉

```tsx
<Modal open={open} title="添加节点" width={MODAL_WIDTH.M} onCancel={close}
  footer={<ModalFooter onCancel={close} onOk={submit} loading={saving} />}>
  <Form layout="vertical">...</Form>
</Modal>
```

- 宽度只用三档 `MODAL_WIDTH.S`（520，简单表单和确认）/ `M`（720，普通表单）/ `L`（960，宽表单和表格）。抽屉用 `DRAWER_WIDTH.S`（520）/ `L`（720）。
- `ModalFooter`：取消在左，主按钮在右。可选 `okText`、`cancelText`、`loading`、`okDisabled`；危险操作传 `danger`，主按钮变成 primary+danger。表单要提交到页脚之外时，用 `okButtonProps={{ htmlType: 'submit', form: 'form-id' }}`。

## 错误与警告反馈

```tsx
const feedback = useFeedback()
feedback.error(t('publishFailed'), errorText(error))
feedback.error('生成失败', { detail: reason, actions: [{ label: '去 DNS 配置', primary: true, onClick: goDns }, { label: '重新生成', onClick: retry }] })
feedback.warning(t('selectNodeFirst'))
```

- 错误、警告一律用 `useFeedback()` 弹居中弹窗：标题 + 原因（可选）+ 下一步按钮（可选）+ 必有的「知道了」。右上角 ×、Esc、点遮罩也能关。不要再用 `message.error/warning`、`notification.error/warning`，它们在页面顶部一闪而过，用户看不到。
- 同一条反馈（类型 + 标题 + 原因文本相同，或同一个 `key`）在弹窗还开着时再触发，不会叠第二个；关掉后再触发会重新弹。
- 下一步按钮点了先关弹窗再执行。至多一个 `primary`；有 primary 时「知道了」是次按钮。
- 排版对齐管理端 iView `Modal.confirm`：28px 图标与标题同一行，标题 16px / 500，正文 14px 左缩进 40px 与标题对齐；所有按钮（下一步、页面传入的 `action`、「知道了」）在底部同一行右对齐，主按钮在最右。
- 标题只放简短原因。文本末尾的「（请求 ID：xxx）」「(Request ID: xxx)」由组件自动拆出，在正文下方以小字一行显示并可复制；带请求 ID 的服务端整句（如「请求内容无效，请检查输入」）首分句留在标题，其余进正文。页面不用自己拆。
- 字段校验类错误（前端校验、400 且带 `details.field`）不弹窗：标在对应字段下方（`form.setFields` / `validateStatus` + `help`，或字段下的 `role="alert"` 提示行）。只有非字段性失败才弹窗。
- 不直接调用 `Modal.error` / `Modal.warning` / `modal.error` / `modal.warning`（守卫 `feedback-static.guard.test.ts`）；`modal.confirm` 照常用，共享样式已把它统一到同一组尺寸。
- 成功类轻提示（「保存成功」「已复制」）继续用 `App.useApp().message.success`，不需要用户确认；中性提示（「未修改」）用 `message.info`。
- 需要页面上下文（路由、查询）的就地说明，用受控的 `<FeedbackDialog open type title detail actions onClose />`，样式和按钮与 `useFeedback()` 相同（例：站点 CNAME 列的「生成失败」标记，点开看原因）。

### 字段错误就地显示

```tsx
const [form] = Form.useForm()
const markFields = useFormSubmitError(form, { display_name: 'displayName' })
const save = useMutation({ mutationFn, onError: (error) => markFields(error, () => feedback.error(errorText(error))) })

const [notice, setNotice] = useState<string>()
<Button onClick={() => (selected.length ? merge() : setNotice(t('selectFirst')))}>合并</Button>
<InlineNotice onClose={() => setNotice(undefined)}>{notice}</InlineNotice>
```

- `useFormSubmitError(form, map?)` 返回 `(error, fallback?) => boolean`：错误码是 `validation_error` / `invalid_request` / `invalid`（市场端）/ `*_validation_error`，且带 `field`（或 `fields` 列表、`details.field`）时，标到同名 `Form.Item`（`origins[0].host`、`origins.0.host` 都解析成嵌套路径；`map` 把后端键映射到表单名，可带按 reason 的页面文案），滚到第一个错误字段，返回 true；表单上没有这个字段或不是字段错误时执行 `fallback`（共享弹窗）并返回 false。
- reason 文案内置中/繁/英（`required`、`too_long`、`invalid_format` 等，未知按「填写的内容不符合要求」）；页面要自己的文案传 `options.message`。没有 hook 的场景用 `applyFormSubmitError(form, error, options)`。
- 运营端、授权门户的 `applyApiFieldError` 已改为委托它，原调用不变。
- `InlineNotice`：没有字段可挂的前端校验（「请先选择授权/域名/待合并项」「上传文件类型不符」「安装命令来源无效」）放在触发按钮或操作区紧下方，错误/警告两态，`role="alert"`，传 `onClose` 才有 ×，内容为空不渲染。不要再为这类校验弹窗。

### 写入结果未知（锁住一块内容）

```tsx
{uncertain ? <OutcomeUnknown title={t('uncertainty.title')} detail={t('uncertainty.description')}
  action={<><Button size="small" onClick={retry}>按原请求重试</Button><Button size="small" onClick={abandon}>放弃并刷新</Button></>} />
  : writeError ? <FeedbackWhen title={errorText(writeError)} /> : null}
```

- `OutcomeUnknown` 先弹警告弹窗说明情况（可关），同时在原位留一条紧凑恢复条（标题 + 「查看说明」+ `action`），关掉弹窗后仍能重试或放弃。
- 放在它锁住的那块内容旁边（表格、表单、区块的正上方），不要放在页面最顶部或最底部。
- 同一个错误既可能「失败」又可能「结果未知」时拆开：失败走 `FeedbackWhen`，结果未知走 `OutcomeUnknown`。

### 页内 Alert 什么时候还能用

- 事件型错误（提交、保存、发布、生成、加载失败）：用弹窗，不放页内 Alert。
- 持久状态说明（「本站已停用」「该功能未开通」「只读」）：可以留在页内，但要贴着它说明的区块或字段，不要固定在页面最顶部或最底部。
- 表单字段校验：错误贴在字段下（Form.Item），不弹窗。

### 弹窗一定能关

- 每个 `Modal` / `Drawer` 都要有关闭途径：页脚取消/知道了、×、Esc、点遮罩至少一种。`footer={null}` 和 `closable={false}` 不能同时出现，除非正文里自带关闭按钮（守卫测试 `packages/cdnca-ui/src/modal-closable.guard.test.ts` 会扫源码）。
- 不该被打断的步骤（正在提交）可以临时不让关，但完成或失败后必须恢复可关闭。

### 弹窗滚动区不显示滚动条

- `.ant-modal-body` / `.ant-drawer-body` 已在 `styles.css` 统一隐藏滚动条，仍可滚轮、触控板、触摸、键盘滚动；下方还有内容时底部 24px 渐隐，滚到底消失，Tab 聚焦会自动滚到可见。页面不用再写 `scrollbar-width`。
- 弹窗里自己设了 `max-height` + `overflow: auto` 的盒子（列表、长文本 `pre`、协议正文），加类 `cdnca-dialog-scroll`。守卫测试 `packages/cdnca-ui/src/dialog-scroll.guard.test.ts` 会扫源码。
- 表格横向滚动不在此列，滚动条保留，方便发现。

## 其他

- `StatusTag status="success" | "processing" | "warning" | "error" | "default"`：只接受这五种语义状态，不要传 green、red 这类色板名（类型检查会报错）。
- `FormGrid columns={2|3|4}`：对齐的表单栅格，`<FormGrid.Full>` 独占一整行，手机宽度下变成单列。
- 状态色：antd 的 success / warning / error / info 已经跟 `--cdnca-color-success` 等变量统一，页面不要再写死绿色和红色。表头底色走 `--cdnca-color-table-header`。

## 时间范围

```tsx
const [range, setRange] = useState<TimeRangeValue>({ preset: 'last1h', range: resolveTimeRangePreset('last1h', 'hour') })
<TimeRangeFilter value={range} onChange={setRange} precision="hour" maxSpanMs={7 * 86_400_000} minDate={dayjs().subtract(30, 'day')} />
```

- `TimeRangeFilter`：左边一组快捷按钮（默认 今天、昨天、近1小时、近6小时、近12小时、近24小时、近7天、近30天，`presets` 按页面传入或自定义 `{ key, label, range }`），最后是「自定义」；选自定义后右边出现「选择时间范围」框，点开是双月并排日历（`<< < > >>` 翻年翻月，今天下面有圆点），底部左边「选择时间」切到时分，右边「清空」「确定」。全站查询页的时间范围都用它，网站访问日志页除外。
- 受控值 `{ preset, range }`：`preset` 是快捷项 key 或 `'custom'`，`range` 是查询窗口 `[Dayjs, Dayjs]`（清空自定义后为 `null`）。快捷项是相对时间，页面再次查询时用 `resolveTimeRangePreset(preset, precision)` 重新取窗口；URL 参数照旧写 from/to。
- 页面原有边界通过参数保留，不放宽：`precision`（`day` / `hour` / `minute` / `second`，对齐与时分列）、`maxSpanMs`（最大跨度）、`minDate`（保留期）、`maxDate`、`endInclusive`（结束时间含当天，选到 23:59 / 23:59:59；默认选中的日期都是 00:00，在「选择时间」里改时分）。超出保留期或最大跨度的快捷项自动不显示；确定时用 `clampTimeRange` 裁剪。必须有窗口的页面传 `allowClear={false}`。
- 不用 antd `RangePicker` 做自定义：antd 5 带 `showTime` 时只显示一个月，做不到双月并排。

## 高级筛选

```tsx
<AdvancedFilters
  storageKey="block-events"
  primary={<><Input aria-label="域名" ... /><TimeRangeFilter ... /></>}
  items={[{ key: 'clientIp', label: '客户端IP', field: <Input aria-label="客户端IP" ... />, applied: applied.clientIp ?? '' }, ...]}
  onQuery={apply} onReset={reset}
  onClearAdvanced={() => applyWith({ clientIp: '', ... })}
  onRemove={(key) => applyWith({ [key]: '' })}
/>
```

- 筛选条件 ≥5 个的页面用它：工具栏一行只常显 1–3 个最常用条件（时间范围也放 `primary`）+「查询」「重置」+ 最右「高级筛选」按钮；其余条件放 `items`，点按钮在下方展开面板（`columns` 2/3/4 列栅格，窄屏单列），面板内「应用」即查询、「清空高级条件」只清高级项再查询，Enter 应用，Esc 收起并把焦点还给按钮。
- 徽标计数与标签只看 `applied`（已查询生效的值，不是草稿）：按钮显示「高级筛选 · N」，工具栏下方逐项显示「标签：值」，× 调 `onRemove(key)` 由页面清掉该项并重查。
- `storageKey` 有值时展开状态记在 localStorage（`cdnca.advancedFilters.<key>`）。`extra` 放同一行最右侧的页面动作（导出等）。数据与校验留在页面。

## 价格角标

- `PriceBadge plan={在售修订}`：永久免费显示「免费」（礼物图标，绿）；限免显示「限免 N 天」，不足 24 小时「限免 N 小时」（时钟图标，橙，悬浮/读屏给出到期后价格）；限免过期或收费计划显示价格文本（`showPrice={false}` 时不显示）。无动画。插件商店卡片、详情、我的插件、卖家上架列表、运营端条目列表统一用它。
- `priceBadgeState(plan, now)` / `formatPlanPrice(price)`：同一套判定与价格文案，表格排序或文案拼接时复用。
