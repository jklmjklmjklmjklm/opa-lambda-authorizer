package opa

default allow = false

allow {
    url := input.url
    role := input.role
    client := input.client

    data[client][role][url]
}