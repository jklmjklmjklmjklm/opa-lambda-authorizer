package opa

import future.keywords.in

default allow = false

allow {
    some c in data.clients
    c.name == input.client
    some r in c.roles
    r.name == input.role
    allow_action(input.url, r.actions)
}

allow_action(url, actions) {
    actions == "*"
}

allow_action(url, actions) {
    url in actions
}