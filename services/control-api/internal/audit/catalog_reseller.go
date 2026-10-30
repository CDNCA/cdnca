package audit

// 代理商（ADR 0018 RS-01, migration 480).
func init() {
	register(
		e("reseller.profile.create", CategoryAdmin,
			"把租户 {resource} 开通为代理商{changes}",
			"made tenant {resource} a reseller{changes}").f("status", "revision"),
		e("reseller.profile.update", CategoryAdmin,
			"修改代理商 {resource}{changes}",
			"updated reseller {resource}{changes}").f("status", "revision"),
		e("reseller.customer.parent_set", CategoryAdmin,
			"把租户 {resource} 的所属代理商改为 {parent_scope_id}{changes}",
			"set the reseller of tenant {resource} to {parent_scope_id}{changes}").f("parent_scope_id"),
		// RS-05: a reseller suspends / resumes one of its customers (written in
		// both the reseller's and the customer's scope).
		e("reseller.customer.status", CategoryAdmin,
			"代理商把客户用户 {resource} 的状态由 {previous_status} 改为 {status}",
			"reseller set customer user {resource} from {previous_status} to {status}").f("previous_status", "status", "reseller_scope_id", "customer_scope_id"),
		e("reseller.wholesale_price.put", CategoryAdmin,
			"设置批发价表 {price_list} 中线路组 {resource} 的 {period} 批发价{changes}",
			"set the {period} wholesale price of line group {resource} in price list {price_list}{changes}").f("price_list", "line_group_id", "period"),
		e("reseller.wholesale_price.delete", CategoryAdmin,
			"删除批发价表 {price_list} 中线路组 {resource} 的 {period} 价格{changes}",
			"deleted the {period} wholesale price of line group {resource} in price list {price_list}{changes}").f("price_list", "line_group_id", "period"),
	)
}
