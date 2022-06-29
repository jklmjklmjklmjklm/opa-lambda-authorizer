const { loadPolicy } = require("@open-policy-agent/opa-wasm");

const fs = require("fs");
const data = require("./opa/data.json")
const policyWasm = fs.readFileSync("policy.wasm");

exports.handler = async (event, context, callback) => {
  const input = "";

  const policy = await loadPolicy(policyWasm);
  policy.setData(data);

  const result = policy.evaluate(input);

  return {
    isAuthorized: result,
  };
};