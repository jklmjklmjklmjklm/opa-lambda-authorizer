package opa

clients := [
   {
        "name": "clientA",
        "roles": [
            {
                "name": "viewer",
                "actions": [ "GET /items", "GET /items/*" ]
            },
            {
                "name": "maker",
                "actions": [ "GET /items", "POST /items", "GET /items/*", "PUT /items/*", "DELETE /items/*" ]
            }
        ]
   },
   {
        "name": "clientB",
        "roles": [
            {
                "name": "admin",
                "actions": "*"
            },
            {
                "name": "member",
                "actions": [ "GET /books", "POST /books", "GET /books/*", "PUT /books/*", "DELETE /books/*" ]
            }
        ]
   }
]

test_allowed {
    allow
        with input as { "client": "clientA", "role": "viewer", "url": "GET /items" }
        with data.clients as clients
}

test_url_mismatched {
    not allow
        with input as { "client": "clientA", "role": "viewer", "url": "POST /items" }
        with data.clients as clients
}

test_unknown_role {
    not allow
        with input as { "client": "clientA", "role": "approver", "url": "GET /items" }
        with data.clients as clients
}