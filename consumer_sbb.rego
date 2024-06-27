package tenant.rbac

import rego.v1

# By default, deny requests.
default allow := false

# Allow owners to do anything.
allow if {
	user_is_owner
	requested_grant_is_valid
}

# Allow the action if the user is granted permission to perform the action.
allow if {
	# Find grants for the user.
	some grant in user_is_granted

	# Check if the grant permits the action.
	input.action == grant.action
	input.type == grant.type

 	#user_is_minor

	#additional_check
}

tenantid := input.tenantid
user:= input.user
account_number := input.account_number

#sprintf("Hello There! %v", [data.user_tenant_roles.user])


# user_is_owner is true if "ACCOUNT_OWNER" is among the user's roles as per data.user_roles
user_is_owner if "ACCOUNT_OWNER" 
	in data.user_tenant_roles[tenantid][account_number][user].roles

requested_grant_is_valid contains grant if {
	some grant in data.role_grants["ACCOUNT_OWNER"]
	print("Grant:", grant)
}

# user_is_minor is true if "MINOR_USER" is among the user's roles as per data.user_roles
user_is_minor if "MINOR_USER" 
	in data.user_tenant_roles[tenantid][account_number][user].roles

# user_is_granted is a set of grants for the user identified in the request.
# The `grant` will be contained if the set `user_is_granted` for every...
user_is_granted contains grant if {
	print("Entering user_is_granted")
	print("user:", user)
	print("tenantid:", tenantid)
	print("account_number", account_number)
	print("user data :", data.user_tenant_roles[tenantid][account_number][user].roles)
	##.account_number.roles)


	
	# `role` assigned an element of the user_roles for this user...
	some role in data.user_tenant_roles[tenantid][account_number][user].roles

	print("Role:", role)

	# `grant` assigned a single grant from the grants list for 'role'...
	some grant in data.role_grants[role]
	print("Grant:", grant)
}

additional_check if {

	# `role` assigned an element of the user_roles for this user...
	some role in data.user_tenant_roles[tenantid][account_number][user].roles
	# `grant` assigned a single grant from the grants list for 'role'...
	some grant in data.role_grants[role]

	grant.action == "ACCOUNT_TRANSACTION_ACCESS_WITH_LIMIT"

	current_week_expenditure := data.user_attributes[input.user].current_week_expenditure
	print("current_week_expenditure:", current_week_expenditure)

	transaction_amount := input.transaction_amount
	print("input transaction_amount:", transaction_amount)

	weekly_limit := data.user_attributes[input.user].weekly_limit
	print("weekly_limit:", weekly_limit)

	total_expenditure := current_week_expenditure + transaction_amount
	print("total_expenditure:", total_expenditure)

	weekly_limit >= total_expenditure	
}
