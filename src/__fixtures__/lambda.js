exports.event = {
  "version": "2.0",
  "type": "REQUEST",
  "routeArn": "arn:aws:execute-api:us-east-1:123456789012:abcdef123/test/GET/items",
  "identitySource": [
    "root",
    "user"
  ],
  "routeKey": "$default",
  "rawPath": "/items",
  "rawQueryString": "parameter1=value1&parameter1=value2&parameter2=value",
  "cookies": [
    "cookie1",
    "cookie2"
  ],
  "headers": {
    "Authorization": "Bearer token"
  },
  "queryStringParameters": {
    "parameter1": "value1,value2",
    "parameter2": "value"
  },
  "requestContext": {
    "accountId": "123456789012",
    "apiId": "abcdef123",
    "authentication": {
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
    "domainName": "abcdef123.execute-api.us-east-1.amazonaws.com",
    "domainPrefix": "abcdef123",
    "http": {
      "method": "POST",
      "path": "/items",
      "protocol": "HTTP/1.1",
      "sourceIp": "1.1.1.1",
      "userAgent": "Mozilla Firefox"
    },
    "requestId": "75e9569d-f193-477b-9134-ca950428446d",
    "routeKey": "$default",
    "stage": "test",
    "time": "12/Mar/2020:19:03:58 +0000",
    "timeEpoch": 1583348638390
  },
  "pathParameters": {
    "parameter1": "value1"
  },
  "stageVariables": {
    "stageVariable1": "value1",
    "stageVariable2": "value2"
  }
};