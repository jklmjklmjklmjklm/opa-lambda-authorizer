exports.event = {
  "type": "REQUEST",
  "methodArn": "arn:aws:execute-api:us-east-1:123456789012:abcdef123/test/GET/items",
  "resource": "/items",
  "path": "/items",
  "httpMethod": "GET",
  "headers": {
    "Authorization": "Bearer token"
  },
  "queryStringParameters": {
    "parameter1": "value1,value2",
    "parameter2": "value"
  },
  "pathParameters": {
    "parameter1": "value1"
  },
  "stageVariables": {
    "stageVariable1": "value1",
    "stageVariable2": "value2"
  },
  "requestContext": {
    "path": "/items",
    "accountId": "123456789012",
    "resourceId": "abcdef123",
    "stage": "test",
    "requestId": "75e9569d-f193-477b-9134-ca950428446d",
    "identity": {
      "apiKey": "abcdef123",
      "sourceIp": "1.1.1.1",
      "clientCert": {
        "clientCertPem": "CERT_CONTENT",
        "subjectDN": "www.example.com",
        "issuerDN": "Example issuer",
        "serialNumber": "a1:a1:a1:a1:a1:a1:a1:a1:a1:a1:a1:a1:a1:a1:a1:a1",
        "validity": {
          "notBefore": "May 28 12:30:02 2019 GMT",
          "notAfter": "Aug  5 09:36:04 2021 GMT"
        }
      }
    },
    "resourcePath": "/items",
    "httpMethod": "GET",
    "apiId": "abcdef123"
  }
};