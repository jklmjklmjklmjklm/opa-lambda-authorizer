const { loadPolicy } = require("@open-policy-agent/opa-wasm");
const jwt = require("jsonwebtoken");

const fs = require("fs");
const publicKey = fs.readFileSync("./public.pem");
const policyWasm = fs.readFileSync("./opa/policy.wasm");

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
  // TODO retrieve these options from env
  const options = {
    algorithms: [ "RS256" ],
    issuer: "",
    ignoreExpiration: false,
  };

  try {
    return jwt.verify(token, publicKey, options);
  } catch (err) {
    console.log(`Error decoding JWT: ${err}`);
    return null;
  }
}

const response = (isAuthorized) => {
  return { isAuthorized };
};