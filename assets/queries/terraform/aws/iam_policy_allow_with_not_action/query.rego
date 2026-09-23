package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Allow + NotAction + Resource "*" grants every action in every service except the listed
# ones, including actions AWS adds later. The existing IAM queries only read 'Action', so
# this statement passed all of them (e.g. sadcloud's "NotAction": ["ec2:*"] group policy).

CxPolicy[result] {
	resourceType := {"aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy", "aws_iam_policy"}
	resource := input.document[i].resource[resourceType[idx]][name]

	policy := common_lib.get_policy(resource.policy)
	st := common_lib.get_statement(policy)
	statement := st[_]

	common_lib.is_allow_effect(statement)
	common_lib.valid_key(statement, "NotAction")
	common_lib.equalsOrInArray(statement.Resource, "*")

	result := {
		"documentId": input.document[i].id,
		"resourceType": resourceType[idx],
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("%s[%s].policy", [resourceType[idx], name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'policy.Statement' with 'Effect: Allow' should use 'Action', not 'NotAction', on 'Resource: *'",
		"keyActualValue": "'policy.Statement' allows every action except those in 'NotAction' on 'Resource: *'",
		"searchLine": common_lib.build_search_line(["resource", resourceType[idx], name, "policy"], []),
	}
}

CxPolicy[result] {
	resource := input.document[i].data.aws_iam_policy_document[name]
	statements := statement_list(resource)
	statement := statements[idx]

	common_lib.is_allow_effect(statement)
	common_lib.valid_key(statement, "not_actions")
	common_lib.equalsOrInArray(statement.resources, "*")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_iam_policy_document",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_iam_policy_document[%s].statement", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'statement' with effect Allow should use 'actions', not 'not_actions', on resources '*'",
		"keyActualValue": "'statement' allows every action except those in 'not_actions' on resources '*'",
		"searchLine": common_lib.build_search_line(search_path(resource, name, idx), []),
	}
}

# HCL gives a list for several statement blocks and one object for a single block.
statement_list(resource) = s {
	is_array(resource.statement)
	s := resource.statement
} else = s {
	is_object(resource.statement)
	s := [resource.statement]
}

search_path(resource, name, idx) = p {
	is_array(resource.statement)
	p := ["data", "aws_iam_policy_document", name, "statement", idx]
} else = p {
	p := ["data", "aws_iam_policy_document", name, "statement"]
}
