package permit.generated.conditionset

import future.keywords.in

import data.permit.generated.abac.utils.attributes

default resourceset_auditor_2daccess = false

resourceset_auditor_2daccess {
	attributes.resource.status == "Submited"
	attributes.resource.type == "Audit"
}
