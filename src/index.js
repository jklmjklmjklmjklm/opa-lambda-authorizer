const { loadPolicy } = require("@open-policy-agent/opa-wasm");
const jwt = require("jsonwebtoken");

const fs = require("fs");
const policyWasm = fs.readFileSync(__dirname + "/opa/policy.wasm");

const data = require("./opa/data.json");

exports.handler = async (event) => {
  if (!event.headers.Authorization) {
    return response(false);
  }

  const authorization = event.headers["Authorization"].split(" ");
  if (authorization.length != 2) {
    return response(false);
  }

  const scheme = authorization[0];
  if (scheme != "Bearer") {
    return response(false);
  }

  const token = authorization[1];
  const decoded = decode(token);

  const input = {
    url: event.rawPath,
    client: decoded.aud,
    role: decoded.role
  };

  const policy = await loadPolicy(policyWasm);
  policy.setData(data);

  const result = policy.evaluate(JSON.stringify(input));

  return response(result);
};

const decode = (token) => {
  const options = {
    algorithms: process.env.JWT_ALGORITHM.split(","),
    issuer: process.env.JWT_ISSUER,
    ignoreExpiration: process.env.JWT_IGNORE_EXPIRATION,
  };

  try {
    const publicKey = process.env.PUBLIC_KEY.replace(/\\n/g, '\n');
    return jwt.verify(token, publicKey, options);
  } catch (err) {
    console.log(`Error decoding JWT: ${err}`);
    return null;
  }
}

const response = (isAuthorized) => {
  return { isAuthorized };
};