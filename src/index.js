const { loadPolicy } = require("@open-policy-agent/opa-wasm");
const jwt = require("jsonwebtoken");

const fs = require("fs");
const policyWasm = fs.readFileSync(__dirname + "/../bin/policy.wasm");

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
  if (!decoded) {
    return response(false);
  }

  const input = {
    url: event.rawPath,
    client: decoded.aud,
    role: decoded.role
  };

  const policy = await loadPolicy(policyWasm);
  policy.setData(data);

  const resultSet = policy.evaluate(JSON.stringify(input));
  return response(resultSet[0].result);
};

const decode = (token) => {
  try {
    const options = {
      algorithms: process.env.JWT_ALGORITHM.split(","),
      issuer: process.env.JWT_ISSUER,
      ignoreExpiration: ("true" === process.env.JWT_IGNORE_EXPIRATION),
    };

    const publicKey = process.env.PUBLIC_KEY.replace(/\\n/g, '\n');
    return jwt.verify(token, publicKey, options);
  } catch (err) {
    console.log(`Error decoding JWT :: ${err.message}`);
    return null;
  }
}

const response = (isAuthorized) => {
  return { isAuthorized };
};