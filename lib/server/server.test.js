import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  test,
} from "@jest/globals";

import { isWin } from "../helpers/utils.js";
import {
  isAllowedHost,
  isAllowedPath,
  isAllowedWinPath,
  parseQueryString,
  parseValue,
} from "./server.js";

test("parseValue tests", () => {
  expect(parseValue("foo")).toEqual("foo");
  expect(parseValue("foo\n")).toEqual("foo");
  expect(parseValue("foo\r\n")).toEqual("foo");
  expect(parseValue(1)).toEqual(1);
  expect(parseValue("true")).toEqual(true);
  expect(parseValue("false")).toEqual(false);
  expect(parseValue(["foo", "bar", 42])).toEqual(["foo", "bar", 42]);
  expect(() => parseValue({ foo: "bar" })).toThrow(TypeError);
  expect(() => parseValue([42, "foo", { foo: "bar" }])).toThrow(TypeError);
  expect(() => parseValue([42, "foo", new Error()])).toThrow(TypeError);
  expect(() => parseValue(["foo", "bar", new String(42)])).toThrow(TypeError);
  expect(parseValue(true)).toEqual(true);
  expect(parseValue(false)).toEqual(false);
});

describe("parseQueryString tests", () => {
  it("prioritizes q over body and calls parseValue for each allowed param", () => {
    const q = { foo: "1", excludeType: ["2"] };
    const body = {
      foo: "x",
      excludeType: ["3"],
      technique: ["manifest-analysis"],
    };
    const options = {};
    const result = parseQueryString(q, body, options);
    expect(result.foo).toBeUndefined();
    expect(result.excludeType).toEqual(["2"]);
    expect(result.technique).toEqual(["manifest-analysis"]);
  });

  it("splits type into projectType and removes type", () => {
    const options = { type: "a,b,c" };
    const result = parseQueryString({}, {}, options);
    expect(result.projectType).toEqual(["a", "b", "c"]);
    expect(result.type).toBeUndefined();
  });

  it("sets installDeps to false for pre-build lifecycle", () => {
    const options = { lifecycle: "pre-build" };
    const result = parseQueryString({}, {}, options);
    expect(result.installDeps).toBe(false);
  });
});

describe("isAllowedHost()", () => {
  let originalHosts;

  beforeEach(() => {
    originalHosts = process.env.CDXGEN_SERVER_ALLOWED_HOSTS;
  });

  afterEach(() => {
    process.env.CDXGEN_SERVER_ALLOWED_HOSTS = originalHosts;
  });

  it("returns true if CDXGEN_SERVER_ALLOWED_HOSTS is not set", () => {
    delete process.env.CDXGEN_SERVER_ALLOWED_HOSTS;
    expect(isAllowedHost("anything")).toBe(true);
  });

  it("returns true for a hostname that is in the list", () => {
    process.env.CDXGEN_SERVER_ALLOWED_HOSTS = "foo.com,bar.com";
    expect(isAllowedHost("foo.com")).toBe(true);
    expect(isAllowedHost("bar.com")).toBe(true);
  });

  it("returns false for a hostname not in the list", () => {
    process.env.CDXGEN_SERVER_ALLOWED_HOSTS = "foo.com,bar.com";
    expect(isAllowedHost("baz.com")).toBe(false);
  });

  it("treats an empty-string env var as unset (returns true)", () => {
    process.env.CDXGEN_SERVER_ALLOWED_HOSTS = "";
    expect(isAllowedHost("whatever")).toBe(true);
  });
});

describe("isAllowedPath()", () => {
  let originalPaths;

  beforeEach(() => {
    originalPaths = process.env.CDXGEN_SERVER_ALLOWED_PATHS;
  });

  afterEach(() => {
    process.env.CDXGEN_SERVER_ALLOWED_PATHS = originalPaths;
  });

  it("returns true if CDXGEN_SERVER_ALLOWED_PATHS is not set", () => {
    delete process.env.CDXGEN_SERVER_ALLOWED_PATHS;
    expect(isAllowedPath("/any/path")).toBe(true);
  });

  it("returns true for paths that start with an allowed prefix", () => {
    process.env.CDXGEN_SERVER_ALLOWED_PATHS = "/api,/public";
    expect(isAllowedPath("/api/resource")).toBe(true);
    expect(isAllowedPath("/public/index.html")).toBe(true);
  });

  it("returns false for paths that do not match any prefix", () => {
    process.env.CDXGEN_SERVER_ALLOWED_PATHS = "/api,/public";
    expect(isAllowedPath("/private/data")).toBe(false);
  });

  it("treats an empty-string env var as unset (returns true)", () => {
    process.env.CDXGEN_SERVER_ALLOWED_PATHS = "";
    expect(isAllowedPath("/anything")).toBe(true);
  });
});

describe("isAllowedWinPath windows tests()", () => {
  it("returns false for windows device name paths", () => {
    if (isWin) {
      expect(isAllowedWinPath("CON:../foo")).toBe(false);
      expect(isAllowedWinPath("X:\\foo\\..\\bar")).toBe(true);
      expect(isAllowedWinPath("C:\\Users")).toBe(true);
      expect(isAllowedWinPath("C:\\🚀")).toBe(true);
      expect(isAllowedWinPath("C:")).toBe(true);
      expect(isAllowedWinPath("c:")).toBe(true);
      expect(isAllowedWinPath("CON:")).toBe(false);
      expect(isAllowedWinPath("COM¹:")).toBe(false);
      expect(isAllowedWinPath("COM¹:../foo")).toBe(false);
      for (const d of [
        "PRN:.\\..\\bar",
        "LpT5:/another/path",
        "PRN:.././../etc/passwd",
        "AUX:/foo\\bar/baz",
        "COM¹:/printer/foo",
        "LPT³:/C:\\Users\\cdxgen//..\\",
        "COM²:LPT³:.\\../../..\\",
        "С:\\",
        "Ϲ:\\",
        "Ⅽ:\\",
        "C\u0301:\\",
        "C\\u0308:\\",
        "C\u00A0:\\",
        "C\u2000:\\",
        "C\u2003:\\",
        "C\\u202E:\\",
        "C\\u202D:\\",
        "😀:\\",
        "$:\\",
        "CD:\\",
        "ABC:\\",
        "con:\\",
        "Con:\\",
        "cOn:\\",
        "COM1.txt:\\",
        "C\\u200B:\\",
        "C\\u200D:\\",
        "C\\\\u29F5\\",
        "🚀:\\",
        "⚡:\\",
      ]) {
        expect(isAllowedWinPath(d)).toBe(false);
      }
    }
  });
});
