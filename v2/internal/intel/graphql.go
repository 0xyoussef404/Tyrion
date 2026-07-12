package intel

import "strings"

// IntrospectionQuery is the standard GraphQL introspection query, minimized.
const IntrospectionQuery = `{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { name kind fields { name } } } }"}`

// IntrospectionCurl builds a ready-to-run introspection probe for an endpoint.
func IntrospectionCurl(url string) string {
	return "curl -sk -X POST '" + url + "' -H 'Content-Type: application/json' -d '" + IntrospectionQuery + "'"
}

// GraphQLOpClass classifies a GraphQL operation name by its likely impact, so
// the workspace can prioritize administrative / financial mutations.
func GraphQLOpClass(name string) string {
	l := strings.ToLower(name)
	switch {
	case containsAny(l, "delete", "remove", "drop", "revoke", "disable"):
		return "destructive"
	case containsAny(l, "pay", "charge", "refund", "transfer", "withdraw", "invoice", "billing", "credit"):
		return "financial"
	case containsAny(l, "admin", "role", "permission", "grant", "promote", "impersonate", "sudo"):
		return "administrative"
	case containsAny(l, "create", "add", "update", "set", "edit", "insert", "register", "invite"):
		return "write"
	default:
		return "read"
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
