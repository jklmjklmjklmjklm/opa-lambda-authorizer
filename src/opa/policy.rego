package opa

import future.keywords.in

default allow = false

allow {
    some c in data.clients
    c.name == input.client
    some r in c.roles
    r.name == input.role
    is_allowed(input.url, r.urls)
}

is_allowed(url, urls) {
    urls == "*"
}

is_allowed(url, urls) {
	some u in urls
	glob.match(u, [ "/" ], url)
}

is_allowed(url, urls) {
    url in urls
}