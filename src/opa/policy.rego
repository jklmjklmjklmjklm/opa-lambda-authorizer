package opa

import future.keywords.in

default allow = false

allow {
    some c in data.clients
    c.name == input.client
    some r in c.roles
    r.name == input.role
    input.url in r.actions
}