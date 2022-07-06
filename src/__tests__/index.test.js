const jwt = require("jsonwebtoken");

const index = require("../index");

const jwtFixtures = require("../__fixtures__/jwt");

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

    const token = createToken({ role: "viewer" }, options);

    const response = await index.handler({ headers: { Authorization: `Bearer ${token}` } });
    expect(response).toHaveProperty("isAuthorized");
    expect(response.isAuthorized).toBe(false);
    expect(console.log).toHaveBeenCalledWith(`Error decoding JWT :: jwt issuer invalid. expected: ${process.env.JWT_ISSUER}`);
  });

  test("should return isAuthorized=false when JWT is expired", async () => {
    const options = jwtFixtures.signOptions;
    options.expiresIn = "30m";

    const payload = {
      role: "viewer",
      iat: Math.floor(Date.now() / 1000) - (60 * 60) // backdate 1h
    }
    const token = createToken(payload, options);

    const response = await index.handler({ headers: { Authorization: `Bearer ${token}` } });
    expect(response).toHaveProperty("isAuthorized");
    expect(response.isAuthorized).toBe(false);
    expect(console.log).toHaveBeenCalledWith("Error decoding JWT :: jwt expired");
  });

  test("should return isAuthorized=false when public key is invalid", async () => {
    const token = createToken({ role: "viewer" }, jwtFixtures.signOptions);
    process.env.PUBLIC_KEY = "Some random public key";

    const response = await index.handler({ headers: { Authorization: `Bearer ${token}` } });
    expect(response).toHaveProperty("isAuthorized");
    expect(response.isAuthorized).toBe(false);
    expect(console.log).toHaveBeenCalledWith(`Error decoding JWT :: error:0909006C:PEM routines:get_name:no start line`);
  });

  // ===== Payload ===== //

  test.todo("should return response payload of 2.0 format");
  test.todo("should return isAuthorized=false when denied");
  test.todo("should return isAuthorized=true when allowed");
});

const createToken = (payload, options) => {
  return jwt.sign(payload, jwtFixtures.privateKey, options);
};