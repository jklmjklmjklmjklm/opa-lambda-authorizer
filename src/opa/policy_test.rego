package opa

clients := [
   {
        "name": "clientA",
        "roles": [
            {
                "name": "viewer",
                "urls": [ "GET /items", "GET /items/*" ]
            },
            {
                "name": "maker",
                "urls": [ "GET /items", "POST /items", "GET /items/*", "PUT /items/*", "DELETE /items/*" ]
            }
        ]
   },
   {
        "name": "clientB",
        "roles": [
            {
                "name": "admin",
                "urls": "*"
            },
            {
                "name": "member",
                "urls": [ "GET /books", "POST /books", "GET /books/*", "PUT /books/*", "DELETE /books/*" ]
            }
        ]
   }
]

test_allowed {
    allow
        with input as { "client": "clientA", "role": "viewer", "url": "GET /items" }
        with data.clients as clients
}

test_role_not_allowed_to_access_url {
    not allow
        with input as { "client": "clientA", "role": "viewer", "url": "POST /items" }
        with data.clients as clients
}

test_unknown_url {
    not allow
        with input as { "client": "clientA", "role": "viewer", "url": "GET /pets" }
        with data.clients as clients
}

test_url_mismatch {
    not allow
        with input as { "client": "clientA", "role": "viewer", "url": "GET /books" }
        with data.clients as clients
}

test_unknown_role {
    not allow
        with input as { "client": "clientA", "role": "approver", "url": "GET /items" }
        with data.clients as clients
}

test_role_mismatch {
    not allow
        with input as { "client": "clientB", "role": "viewer", "url": "GET /books" }
        with data.clients as clients
}

test_unknown_client {
    not allow
        with input as { "client": "clientC", "role": "approver", "url": "GET /items" }
        with data.clients as clients
}

test_allow_wildcard {
    allow
        with input as { "client": "clientB", "role": "admin", "url": "GET /items" }
        with data.clients as clients
}

test_allow_glob {
    allow
        with input as { "client": "clientA", "role": "maker", "url": "PUT /items/123" }
        with data.clients as clients
}