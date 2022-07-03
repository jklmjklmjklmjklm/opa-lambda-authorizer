package opa

import future.keywords.in

default allow = false

allow {
    some i in data.clients
    data.clients[i].name == input.client
    some j in data.clients[i].roles
    data.clients[i].roles[j] == input.role
    input.url in data.clients[i].roles[j].actions
}