const index = require("./index");

test("handler should be a function", () => {
  expect(index).toHaveProperty("handler");
  expect(typeof index.handler).toBe("function");
});