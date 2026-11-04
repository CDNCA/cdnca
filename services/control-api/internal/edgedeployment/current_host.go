package edgedeployment

// CurrentHostDeployment is the SQL condition that the node_deployments row
// aliased deployment was created for the node's current host: at or after the
// node's newest enrollment certificate (issuance_kind 'initial'; renewals and
// recoveries are 'renewal'). A reinstall ("重装此节点", re_enrollment) enrolls
// a new host under the same node ID, so what the previous host held (a healthy
// deployment) or was being sent is no proof the new host has it. A node never
// re-enrolled has one enrollment, before all its deployments, so the condition
// keeps its whole history.
func CurrentHostDeployment(deployment string) string {
	return deployment + `.created_at >= COALESCE((SELECT max(enrollment.issued_at) FROM node_certificates enrollment
		WHERE enrollment.node_id=` + deployment + `.node_id AND enrollment.issuance_kind='initial'),'-infinity')`
}
