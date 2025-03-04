package permit.generated.conditionset.rules

import future.keywords.in

import data.permit.generated.abac.utils.attributes
import data.permit.generated.abac.utils.condition_set_permissions
import data.permit.generated.conditionset

default _5f5f_5f5fautogen_5f5fEditor_5fon_5fAudit_5fauditor_5f2daccess = false

_5f5f_5f5fautogen_5f5fEditor_5fon_5fAudit_5fauditor_5f2daccess {
	conditionset.userset__5f_5fautogen_5fEditor
	conditionset.resourceset_auditor_2daccess
	input.action in condition_set_permissions.__autogen_Editor["auditor-access"][input.resource.type]
}
