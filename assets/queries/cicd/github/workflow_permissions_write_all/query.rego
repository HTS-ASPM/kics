package Cx

import data.generic.common as common_lib

# 'permissions: write-all' at the workflow level applies to every job; at the job level it
# applies to that job. Either way a compromised step or third-party action gets a token that
# can write to every scope.

CxPolicy[result] {
	permissions := input.document[i].permissions
	is_write_all(permissions)

	result := {
		"documentId": input.document[i].id,
		"searchKey": "permissions",
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'permissions' should list only the scopes the workflow needs",
		"keyActualValue": "'permissions' is 'write-all'",
		"searchLine": common_lib.build_search_line(["permissions"], []),
	}
}

CxPolicy[result] {
	permissions := input.document[i].jobs[j].permissions
	is_write_all(permissions)

	result := {
		"documentId": input.document[i].id,
		"searchKey": sprintf("jobs.%s.permissions", [j]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'jobs.%s.permissions' should list only the scopes the job needs", [j]),
		"keyActualValue": sprintf("'jobs.%s.permissions' is 'write-all'", [j]),
		"searchLine": common_lib.build_search_line(["jobs", j, "permissions"], []),
	}
}

is_write_all(permissions) {
	is_string(permissions)
	lower(trim_space(permissions)) == "write-all"
}
