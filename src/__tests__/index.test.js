const opaWasm = require("@open-policy-agent/opa-wasm");
const jwt = require("jsonwebtoken");

const index = require("../index");
const data  = require("../opa/data.json");

const jwtFixtures = require("../__fixtures__/jwt");
const lambdaFixtures = require("../__fixtures__/lambda");

jest.spyOn(console, "log");
jest.mock("@open-policy-agent/opa-wasm");

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
    const payload = lambdaFixtures.event;
    delete payload.headers["Authorization"]

    const response = await index.handler(payload);
    expect(response).toHaveProperty("isAuthorized");
    expect(response.isAuthorized).toBe(false);
  });

  test("should return isAuthorized=false when Authorization header is not of valid format", async () => {
    const payload = lambdaFixtures.event;
    payload.headers["Authorization"] = "random";

    const response = await index.handler(payload);
    expect(response).toHaveProperty("isAuthorized");
    expect(response.isAuthorized).toBe(false);
  });

  test("should return isAuthorized=false when Authorization header is not of Bearer scheme", async () => {
    const payload = lambdaFixtures.event;
    payload.headers["Authorization"] = "Basic token";

    const response = await index.handler(payload);
    expect(response).toHaveProperty("isAuthorized");
    expect(response.isAuthorized).toBe(false);
  });

  // ===== JWT verification ===== //

  test("should return isAuthorized=false when JWT verification failed", async () => {
    const error = "JWT verification failed";
    const verifyMock = jest.spyOn(jwt, "verify");
    verifyMock.mockImplementation(() => { throw new Error(error); });

    const payload = lambdaFixtures.event;
    payload.headers["Authorization"] = "Bearer token";

    const response = await index.handler(payload);
    expect(response).toHaveProperty("isAuthorized");
    expect(response.isAuthorized).toBe(false);
    expect(console.log).toHaveBeenCalledWith(`Error decoding JWT :: ${error}`);

    // for some reason jest.clearAllMocks() does not work on local mocks
    verifyMock.mockRestore();
  });

  test("should return isAuthorized=false when JWT issuer is invalid", async () => {
    const options = jwtFixtures.signOptions;
    options.issuer = "auth.other.com";

    const token = createToken({ role: "viewer" }, options);

    const payload = lambdaFixtures.event;
    payload.headers["Authorization"] = `Bearer ${token}`;

    const response = await index.handler(payload);
    expect(response).toHaveProperty("isAuthorized");
    expect(response.isAuthorized).toBe(false);
    expect(console.log).toHaveBeenCalledWith(`Error decoding JWT :: jwt issuer invalid. expected: ${process.env.JWT_ISSUER}`);
  });

  test("should return isAuthorized=false when JWT is expired", async () => {
    const options = jwtFixtures.signOptions;
    options.expiresIn = "30m";

    const tokenPayload = {
      role: "viewer",
      iat: Math.floor(Date.now() / 1000) - (60 * 60) // backdate 1h
    }
    const token = createToken(tokenPayload, options);

    const payload = lambdaFixtures.event;
    payload.headers["Authorization"] = `Bearer ${token}`;

    const response = await index.handler(payload);
    expect(response).toHaveProperty("isAuthorized");
    expect(response.isAuthorized).toBe(false);
    expect(console.log).toHaveBeenCalledWith("Error decoding JWT :: jwt expired");
  });

  test("should return isAuthorized=false when public key is invalid", async () => {
    const token = createToken({ role: "viewer" }, jwtFixtures.signOptions);
    process.env.PUBLIC_KEY = "Some random public key";

    const payload = lambdaFixtures.event;
    payload.headers["Authorization"] = `Bearer ${token}`;

    const response = await index.handler(payload);
    expect(response).toHaveProperty("isAuthorized");
    expect(response.isAuthorized).toBe(false);
    expect(console.log).toHaveBeenCalledWith(`Error decoding JWT :: error:0909006C:PEM routines:get_name:no start line`);
  });

  // ===== OPA ===== //
  test("should provide the correct inputs to OPA", async () => {
    const setDataMock = jest.fn();
    const evaluateMock = jest.fn(() => { return true; });
    opaWasm.loadPolicy.mockResolvedValue({
      setData: setDataMock,
      evaluate: evaluateMock
    });

    const token = createToken({ role: "viewer" }, jwtFixtures.signOptions);

    const payload = lambdaFixtures.event;
    payload.headers["Authorization"] = `Bearer ${token}`;

    const response = await index.handler(payload);
    expect(response).toHaveProperty("isAuthorized");
    expect(response.isAuthorized).toBe(true);
    expect(setDataMock).toHaveBeenCalledWith(data);
    expect(evaluateMock).toHaveBeenCalledWith(JSON.stringify({
      url: "/items",
      client: "clientA",
      role: "viewer"
    }));
  });

  // ===== Payload ===== //

  test.todo("should return response payload of 2.0 format");
  test.todo("should return isAuthorized=false when denied");
  test.todo("should return isAuthorized=true when allowed");
});

const createToken = (payload, options) => {
  return jwt.sign(payload, jwtFixtures.privateKey, options);
};