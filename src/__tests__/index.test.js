const fs = require("fs");
const jwt = require("jsonwebtoken");

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

jest.spyOn(console, "log");

describe(".handler", () => {
  beforeEach(() => {
    process.env.JWT_ISSUER            = jwtFixtures.signOptions.issuer;
    process.env.JWT_ALGORITHM         = jwtFixtures.signOptions.algorithm;
    process.env.JWT_IGNORE_EXPIRATION = "false";

    process.env.PUBLIC_KEY = jwtFixtures.publicKey;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  test("should be a function", () => {
    expect(index).toHaveProperty("handler");
    expect(typeof index.handler).toBe("function");
  });

  // ===== Authorization header ===== //

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

  // ===== JWT verification ===== //

  test("should return isAuthorized=false when JWT verification failed", async () => {
    const error = "JWT verification failed";
    const verifyMock = jest.spyOn(jwt, "verify");
    verifyMock.mockImplementation(() => { throw new Error(error); });

    const response = await index.handler({ headers: { Authorization: "Bearer token" } });
    expect(response).toHaveProperty("isAuthorized");
    expect(response.isAuthorized).toBe(false);
    expect(console.log).toHaveBeenCalledWith(`Error decoding JWT :: ${error}`);

    // for some reason jest.clearAllMocks() does not work on local mocks
    verifyMock.mockRestore();
  });

  test("should return isAuthorized=false when JWT issuer is invalid", async () => {
    const options = jwtFixtures.signOptions;
    options.issuer = "auth.other.com";

    const token = createToken({ role: "admin" }, options);

    const response = await index.handler({ headers: { Authorization: `Bearer ${token}` } });
    expect(response).toHaveProperty("isAuthorized");
    expect(response.isAuthorized).toBe(false);
    expect(console.log).toHaveBeenCalledWith(`Error decoding JWT :: jwt issuer invalid. expected: ${process.env.JWT_ISSUER}`);
  });

  test("should return isAuthorized=false when JWT is expired", async () => {
    const options = jwtFixtures.signOptions;
    options.expiresIn = "30m";

    const payload = {
      role: "admin",
      iat: Math.floor(Date.now() / 1000) - (60 * 60) // backdate 1h
    }
    const token = createToken(payload, options);

    const response = await index.handler({ headers: { Authorization: `Bearer ${token}` } });
    expect(response).toHaveProperty("isAuthorized");
    expect(response.isAuthorized).toBe(false);
    expect(console.log).toHaveBeenCalledWith("Error decoding JWT :: jwt expired");
  });

  test.todo("should return isAuthorized=false when public key is invalid");

  // ===== Payload ===== //

  test.todo("should return response payload of 2.0 format");
  test.todo("should return isAuthorized=false when denied");
  test.todo("should return isAuthorized=true when allowed");
});

const createToken = (payload, options) => {
  return jwt.sign(payload, jwtFixtures.privateKey, options);
};