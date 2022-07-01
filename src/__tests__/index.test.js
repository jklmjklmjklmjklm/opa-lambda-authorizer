const index = require("../index");

const jwtFixtures = require("../__fixtures__/jwt");
const event = {
  "version": "2.0",
  "type": "REQUEST",
  "routeArn": "arn:aws:execute-api:us-east-1:123456789012:abcdef123/test/GET/request",
  "identitySource": ["user1", "123"],
  "routeKey": "$default",
  "rawPath": "/my/path",
  "rawQueryString": "parameter1=value1&parameter1=value2&parameter2=value",
  "cookies": ["cookie1", "cookie2"],
  "headers": {
    "Header1": "value1",
    "Header2": "value2"
  },
  "queryStringParameters": {
    "parameter1": "value1,value2",
    "parameter2": "value"
  },
  "requestContext": {
    "accountId": "123456789012",
    "apiId": "api-id",
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
    "domainName": "id.execute-api.us-east-1.amazonaws.com",
    "domainPrefix": "id",
    "http": {
      "method": "POST",
      "path": "/my/path",
      "protocol": "HTTP/1.1",
      "sourceIp": "IP",
      "userAgent": "agent"
    },
    "requestId": "id",
    "routeKey": "$default",
    "stage": "$default",
    "time": "12/Mar/2020:19:03:58 +0000",
    "timeEpoch": 1583348638390
  },
  "pathParameters": { "parameter1": "value1" },
  "stageVariables": { "stageVariable1": "value1", "stageVariable2": "value2" }
};

describe(".handler", () => {
  beforeEach(() => {
    process.env.JWT_ISSUER            = jwtFixtures.signOptions.issuer;
    process.env.JWT_ALGORITHM         = jwtFixtures.signOptions.algorithm;
    process.env.JWT_IGNORE_EXPIRATION = "false";

    process.env.PUBLIC_KEY = jwtFixtures.publicKey;
  });

  test("should be a function", () => {
    expect(index).toHaveProperty("handler");
    expect(typeof index.handler).toBe("function");
  });

  test("should return isAuthorized=false when Authorization header is not present", async () => {
    const response = await index.handler({ headers: {} });
    expect(response).toHaveProperty("isAuthorized");
    expect(response.isAuthorized).toBe(false);
  });

  test("should return isAuthorized=false when Authorization header is not of valid format", async () => {
    const response = await index.handler({ headers: { Authorization: "random" } });
    expect(response).toHaveProperty("isAuthorized");
    expect(response.isAuthorized).toBe(false);
  });

  test("should return isAuthorized=false when Authorization header is not of Bearer scheme", async () => {
    const response = await index.handler({ headers: { Authorization: "Basic token" } });
    expect(response).toHaveProperty("isAuthorized");
    expect(response.isAuthorized).toBe(false);
  });

  test.todo("should return response payload of 2.0 format");
  test.todo("should return isAuthorized=false when denied");
  test.todo("should return isAuthorized=true when allowed");
});