import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).parents[1] / "chrome-extension"


def _run_background_scenario(scenario: str) -> object:
    source = (ROOT / "background.js").read_text()
    harness = f"""
const vm = require("node:vm");
const context = {{
  URL,
  setTimeout,
  clearTimeout,
  queueMicrotask,
  chrome: {{
    runtime: {{
      id: "extension-id",
      getURL: (path) => `chrome-extension://extension-id/${{path}}`,
      connectNative: () => {{ throw new Error("native port not configured"); }},
      onMessage: {{ addListener: () => undefined }},
    }},
    permissions: {{ contains: async () => true }},
    cookies: {{}},
    tabs: {{}},
  }},
}};
vm.createContext(context);
vm.runInContext({json.dumps(source + scenario)}, context);
Promise.resolve(context.__scenarioResult)
  .then((result) => process.stdout.write(JSON.stringify(result)))
  .catch((error) => {{
    process.stderr.write(String(error?.stack || error));
    process.exitCode = 1;
  }});
"""
    completed = subprocess.run(
        ["/usr/bin/env", "node", "-e", harness],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


def test_extension_permissions_bind_authentication_to_the_native_host():
    manifest = json.loads((ROOT / "manifest.json").read_text())

    assert manifest["manifest_version"] == 3
    assert manifest["permissions"] == ["cookies", "tabs", "nativeMessaging"]
    assert manifest["optional_host_permissions"] == ["https://*/*"]
    assert "host_permissions" not in manifest


def test_extension_does_not_log_or_request_broad_browser_access():
    source = "\n".join(path.read_text() for path in ROOT.glob("*.js"))

    assert "console.log" not in source
    for forbidden in ("<all_urls>", "webRequest", "history", "storage", "debugger"):
        assert forbidden not in source
    assert "vpn.example.com" not in source


def test_extension_does_not_receive_callback_capabilities_in_browser_metadata():
    source = "\n".join(path.read_text() for path in ROOT.glob("*.js"))

    assert "window.location.search" not in source
    assert "127.0.0.1" not in source
    assert "nonce" not in source
    assert 'const NATIVE_HOST = "io.github.k0nkupa.meraki_openconnect"' in source
    assert "chrome.runtime.connectNative(NATIVE_HOST)" in source


def test_permission_request_occurs_only_in_setup_button_handler():
    source = (ROOT / "setup.js").read_text()

    assert source.count("chrome.permissions.request") == 1
    handler = source.split('grantButton.addEventListener("click"', 1)[1]
    assert "chrome.permissions.request" in handler
    assert "gatewayOrigin" in source
    assert "profileDigest" in source
    assert "window.location.search" not in source


def test_authentication_checks_exact_dynamic_permission_and_receipt():
    source = (ROOT / "background.js").read_text()

    assert "chrome.permissions.contains({ origins: [exactOrigin] })" in source
    assert "bootstrap.profileDigest" in source
    assert "bootstrap.gatewayOrigin" in source
    assert "GATEWAY_HOST" not in source
    assert "GATEWAY_ORIGIN" not in source


def test_extension_always_disconnects_native_host_after_cookie_cleanup():
    source = (ROOT / "background.js").read_text()

    assert """if (bootstrap) {
        await cleanupAuthentication(bootstrap, cookiesSet, previous);
      }
    } finally {
      native.disconnect();
    }""" in source


def test_extension_removes_returned_token_cookie():
    source = (ROOT / "background.js").read_text()

    assert "removeTokenCookie" in source
    assert "await removeTokenCookie(bootstrap)" in source
    assert source.count("await removeTokenCookie(bootstrap)") == 2


def test_extension_clears_stale_token_before_navigation_and_hands_off_fresh_token():
    result = _run_background_scenario(
        r"""
const events = [];
const sentTokens = [];
let tokenCookie = {
  name: "webvpn",
  value: "stale-token",
  domain: "vpn.example.test",
  path: "/saml/login.html",
  secure: true,
  httpOnly: true,
  sameSite: "strict",
  hostOnly: true,
  session: true,
  storeId: "0",
};
const messageListeners = [];
const disconnectListeners = [];
const port = {
  onMessage: {
    addListener: (listener) => messageListeners.push(listener),
    removeListener: (listener) => {
      const index = messageListeners.indexOf(listener);
      if (index >= 0) messageListeners.splice(index, 1);
    },
  },
  onDisconnect: {
    addListener: (listener) => disconnectListeners.push(listener),
    removeListener: (listener) => {
      const index = disconnectListeners.indexOf(listener);
      if (index >= 0) disconnectListeners.splice(index, 1);
    },
  },
  postMessage: (message) => {
    if (message.type === "bootstrap") {
      queueMicrotask(() => messageListeners[0]({
        type: "bootstrap",
        bootstrap: {
          gatewayOrigin: "https://vpn.example.test",
          loginOrigin: "https://login.example.test",
          profileDigest: `sha256:${"a".repeat(64)}`,
          loginUrl: "https://login.example.test/saml?request=1",
          finalUrl: "https://vpn.example.test/saml/login.html",
          cookieName: "webvpn",
          cookies: [],
        },
      }));
      return;
    }
    if (message.type === "token") {
      sentTokens.push(message.token);
      queueMicrotask(() => messageListeners[0]({ type: "accepted" }));
    }
  },
  disconnect: () => events.push("disconnect"),
};
chrome.runtime.connectNative = () => port;
chrome.cookies.getAll = async ({ name }) =>
  name === "webvpn" && tokenCookie ? [tokenCookie] : [];
chrome.cookies.get = async ({ name }) =>
  name === "webvpn" ? tokenCookie : null;
chrome.cookies.remove = async ({ name }) => {
  if (name === "webvpn" && tokenCookie) {
    const removed = tokenCookie;
    tokenCookie = null;
    events.push("remove-token");
    return removed;
  }
  return null;
};
chrome.cookies.set = async (details) => details;
chrome.tabs.create = async () => {
  events.push("create-tab");
  if (!tokenCookie) {
    tokenCookie = {
      name: "webvpn",
      value: "fresh-token",
      domain: "vpn.example.test",
      path: "/saml/login.html",
      secure: true,
      hostOnly: true,
      session: true,
      storeId: "0",
    };
  }
  return { id: 7 };
};
chrome.tabs.remove = async () => events.push("remove-tab");
globalThis.__scenarioResult = startAuthentication().then(() => ({
  events,
  sentTokens,
  tokenRemains: tokenCookie !== null,
}));
"""
    )

    assert result["sentTokens"] == ["fresh-token"]
    assert result["events"].index("remove-token") < result["events"].index(
        "create-tab"
    )
    assert result["tokenRemains"] is False


def test_token_named_bootstrap_cookie_is_never_installed_snapshotted_or_restored():
    result = _run_background_scenario(
        r"""
const sentTokens = [];
const setCookieNames = [];
let tokenGetAllCount = 0;
let tokenCookie = {
  name: "webvpn",
  value: "stale-token",
  domain: "vpn.example.test",
  path: "/saml/login.html",
  secure: true,
  hostOnly: true,
  session: true,
  storeId: "0",
};
let regularCookies = [];
const messageListeners = [];
const disconnectListeners = [];
const port = {
  onMessage: {
    addListener: (listener) => messageListeners.push(listener),
    removeListener: (listener) => {
      const index = messageListeners.indexOf(listener);
      if (index >= 0) messageListeners.splice(index, 1);
    },
  },
  onDisconnect: {
    addListener: (listener) => disconnectListeners.push(listener),
    removeListener: (listener) => {
      const index = disconnectListeners.indexOf(listener);
      if (index >= 0) disconnectListeners.splice(index, 1);
    },
  },
  postMessage: (message) => {
    if (message.type === "bootstrap") {
      queueMicrotask(() => messageListeners[0]({
        type: "bootstrap",
        bootstrap: {
          gatewayOrigin: "https://vpn.example.test",
          loginOrigin: "https://login.example.test",
          profileDigest: `sha256:${"b".repeat(64)}`,
          loginUrl: "https://login.example.test/saml?request=1",
          finalUrl: "https://vpn.example.test/saml/login.html",
          cookieName: "webvpn",
          cookies: [
            {
              name: "webvpn",
              value: "bootstrap-token",
              domain: "vpn.example.test",
              path: "/saml/login.html",
              secure: true,
              expires: null,
              host_only: true,
            },
            {
              name: "gateway-session",
              value: "temporary-session",
              domain: "vpn.example.test",
              path: "/",
              secure: true,
              expires: null,
              host_only: true,
            },
          ],
        },
      }));
      return;
    }
    if (message.type === "token") {
      sentTokens.push(message.token);
      queueMicrotask(() => messageListeners[0]({ type: "accepted" }));
    }
  },
  disconnect: () => undefined,
};
chrome.runtime.connectNative = () => port;
chrome.cookies.getAll = async ({ name }) => {
  if (name === "webvpn") {
    tokenGetAllCount += 1;
    return tokenCookie ? [tokenCookie] : [];
  }
  return regularCookies.filter((cookie) => cookie.name === name);
};
chrome.cookies.get = async ({ name }) =>
  name === "webvpn" ? tokenCookie : null;
chrome.cookies.remove = async ({ name }) => {
  if (name === "webvpn") {
    const removed = tokenCookie;
    tokenCookie = null;
    return removed;
  }
  const index = regularCookies.findIndex((cookie) => cookie.name === name);
  return index < 0 ? null : regularCookies.splice(index, 1)[0];
};
chrome.cookies.set = async (details) => {
  setCookieNames.push(details.name);
  if (details.name === "webvpn") {
    tokenCookie = { ...details, hostOnly: !("domain" in details) };
    return tokenCookie;
  }
  const cookie = { ...details, hostOnly: !("domain" in details) };
  regularCookies.push(cookie);
  return cookie;
};
chrome.tabs.create = async () => {
  if (!tokenCookie) {
    tokenCookie = {
      name: "webvpn",
      value: "fresh-token",
      domain: "vpn.example.test",
      path: "/saml/login.html",
      secure: true,
      hostOnly: true,
      session: true,
      storeId: "0",
    };
  }
  return { id: 8 };
};
chrome.tabs.remove = async () => undefined;
globalThis.__scenarioResult = startAuthentication().then(() => ({
  sentTokens,
  setCookieNames,
  tokenGetAllCount,
  tokenRemains: tokenCookie !== null,
}));
"""
    )

    assert result == {
        "sentTokens": ["fresh-token"],
        "setCookieNames": ["gateway-session"],
        "tokenGetAllCount": 4,
        "tokenRemains": False,
    }


def test_cookie_details_preserve_chrome_security_and_partition_attributes():
    result = _run_background_scenario(
        r"""
globalThis.__scenarioResult = cookieDetails({
  name: "existing",
  value: "value",
  domain: "vpn.example.test",
  path: "/auth",
  secure: true,
  httpOnly: true,
  sameSite: "strict",
  hostOnly: true,
  session: false,
  expirationDate: 2000000000,
  storeId: "0",
  partitionKey: { topLevelSite: "https://example.test", hasCrossSiteAncestor: false },
}, "https://vpn.example.test");
"""
    )

    assert result == {
        "url": "https://vpn.example.test/auth",
        "name": "existing",
        "value": "value",
        "path": "/auth",
        "secure": True,
        "httpOnly": True,
        "sameSite": "strict",
        "expirationDate": 2000000000,
        "storeId": "0",
        "partitionKey": {
            "topLevelSite": "https://example.test",
            "hasCrossSiteAncestor": False,
        },
    }


def test_temporary_cookie_cleanup_restores_all_same_name_variants_faithfully():
    result = _run_background_scenario(
        r"""
let jar = [
  {
    name: "bootstrap",
    value: "host-value",
    domain: "vpn.example.test",
    path: "/",
    secure: true,
    httpOnly: true,
    sameSite: "strict",
    hostOnly: true,
    session: true,
    storeId: "0",
  },
  {
    name: "bootstrap",
    value: "domain-value",
    domain: ".example.test",
    path: "/",
    secure: true,
    httpOnly: false,
    sameSite: "lax",
    hostOnly: false,
    session: false,
    expirationDate: 2000000000,
    storeId: "0",
  },
];
chrome.cookies.getAll = async ({ name }) => jar.filter((cookie) => cookie.name === name);
chrome.cookies.get = async ({ name }) => jar.find((cookie) => cookie.name === name) || null;
chrome.cookies.remove = async ({ name }) => {
  const index = jar.findIndex((cookie) => cookie.name === name);
  if (index < 0) return null;
  return jar.splice(index, 1)[0];
};
chrome.cookies.set = async (details) => {
  const cookie = {
    ...details,
    domain: details.domain || new URL(details.url).hostname,
    hostOnly: !("domain" in details),
    session: !("expirationDate" in details),
  };
  delete cookie.url;
  jar.push(cookie);
  return cookie;
};
globalThis.__scenarioResult = (async () => {
  const temporary = [{
    name: "bootstrap",
    value: "temporary",
    domain: "vpn.example.test",
    path: "/",
    secure: true,
    expires: null,
    host_only: true,
  }];
  const previous = await setTemporaryCookies(temporary, "https://vpn.example.test");
  await restoreCookies(temporary, previous, "https://vpn.example.test");
  return jar.map(({ name, value, domain, path, secure, httpOnly, sameSite,
    hostOnly, session, expirationDate, storeId }) => ({
      name, value, domain, path, secure, httpOnly, sameSite,
      hostOnly, session, expirationDate, storeId,
    })).sort((left, right) => left.value.localeCompare(right.value));
})();
"""
    )

    assert result == [
        {
            "name": "bootstrap",
            "value": "domain-value",
            "domain": ".example.test",
            "path": "/",
            "secure": True,
            "httpOnly": False,
            "sameSite": "lax",
            "hostOnly": False,
            "session": False,
            "expirationDate": 2000000000,
            "storeId": "0",
        },
        {
            "name": "bootstrap",
            "value": "host-value",
            "domain": "vpn.example.test",
            "path": "/",
            "secure": True,
            "httpOnly": True,
            "sameSite": "strict",
            "hostOnly": True,
            "session": True,
            "storeId": "0",
        },
    ]


def test_temporary_cookie_set_failure_restores_the_cookie_it_already_removed():
    result = _run_background_scenario(
        r"""
let jar = [{
  name: "bootstrap",
  value: "original",
  domain: "vpn.example.test",
  path: "/",
  secure: true,
  httpOnly: true,
  sameSite: "strict",
  hostOnly: true,
  session: true,
  storeId: "0",
}];
chrome.cookies.getAll = async ({ name }) => jar.filter((cookie) => cookie.name === name);
chrome.cookies.remove = async ({ name }) => {
  const index = jar.findIndex((cookie) => cookie.name === name);
  return index < 0 ? null : jar.splice(index, 1)[0];
};
chrome.cookies.set = async (details) => {
  if (details.value === "temporary") throw new Error("synthetic set failure");
  const cookie = {
    ...details,
    domain: details.domain || new URL(details.url).hostname,
    hostOnly: !("domain" in details),
    session: !("expirationDate" in details),
  };
  delete cookie.url;
  jar.push(cookie);
  return cookie;
};
globalThis.__scenarioResult = setTemporaryCookies([{
  name: "bootstrap",
  value: "temporary",
  domain: "vpn.example.test",
  path: "/",
  secure: true,
  expires: null,
  host_only: true,
}], "https://vpn.example.test")
  .then(() => ({ rejected: false, jar }))
  .catch(() => ({ rejected: true, jar }));
"""
    )

    assert result["rejected"] is True
    assert len(result["jar"]) == 1
    assert result["jar"][0]["value"] == "original"
    assert result["jar"][0]["httpOnly"] is True
    assert result["jar"][0]["sameSite"] == "strict"


def test_partial_variant_removal_rolls_back_before_bootstrap_cookie_install():
    result = _run_background_scenario(
        r"""
const installedValues = [];
let removalAttempts = 0;
let jar = [
  {
    name: "bootstrap",
    value: "host-original",
    domain: "vpn.example.test",
    path: "/",
    secure: true,
    httpOnly: true,
    sameSite: "strict",
    hostOnly: true,
    session: true,
    storeId: "0",
  },
  {
    name: "bootstrap",
    value: "domain-original",
    domain: ".example.test",
    path: "/",
    secure: true,
    httpOnly: false,
    sameSite: "lax",
    hostOnly: false,
    session: false,
    expirationDate: 2000000000,
    storeId: "0",
  },
];
chrome.cookies.getAll = async ({ name }) => jar.filter((cookie) => cookie.name === name);
chrome.cookies.remove = async ({ name }) => {
  removalAttempts += 1;
  if (removalAttempts > 1) return null;
  const index = jar.findIndex((cookie) => cookie.name === name);
  return index < 0 ? null : jar.splice(index, 1)[0];
};
chrome.cookies.set = async (details) => {
  installedValues.push(details.value);
  const cookie = {
    ...details,
    domain: details.domain || new URL(details.url).hostname,
    hostOnly: !("domain" in details),
    session: !("expirationDate" in details),
  };
  delete cookie.url;
  jar.push(cookie);
  return cookie;
};
globalThis.__scenarioResult = setTemporaryCookies([{
  name: "bootstrap",
  value: "temporary-bootstrap",
  domain: "vpn.example.test",
  path: "/",
  secure: true,
  expires: null,
  host_only: true,
}], "https://vpn.example.test")
  .then(() => ({ rejected: false, installedValues, jar }))
  .catch(() => ({ rejected: true, installedValues, jar }));
"""
    )

    assert result["rejected"] is True
    assert "temporary-bootstrap" not in result["installedValues"]
    assert {cookie["value"] for cookie in result["jar"]} == {
        "host-original",
        "domain-original",
    }
    restored = next(
        cookie for cookie in result["jar"] if cookie["value"] == "host-original"
    )
    assert restored["httpOnly"] is True
    assert restored["sameSite"] == "strict"
    assert restored["hostOnly"] is True


def test_partial_variant_removal_restores_snapshot_when_followup_query_errors():
    result = _run_background_scenario(
        r"""
const installedValues = [];
let getAllCalls = 0;
let jar = [
  { name: "bootstrap", value: "first-original", domain: "vpn.example.test",
    path: "/", secure: true, httpOnly: true, sameSite: "strict",
    hostOnly: true, session: true, storeId: "0" },
  { name: "bootstrap", value: "second-original", domain: ".example.test",
    path: "/", secure: true, httpOnly: false, sameSite: "lax",
    hostOnly: false, session: true, storeId: "0" },
];
chrome.cookies.getAll = async ({ name }) => {
  getAllCalls += 1;
  if (getAllCalls === 3) throw new Error("synthetic followup query failure");
  return jar.filter((cookie) => cookie.name === name);
};
chrome.cookies.remove = async ({ name }) => {
  const index = jar.findIndex((cookie) => cookie.name === name);
  return index < 0 ? null : jar.splice(index, 1)[0];
};
chrome.cookies.set = async (details) => {
  installedValues.push(details.value);
  const cookie = {
    ...details,
    domain: details.domain || new URL(details.url).hostname,
    hostOnly: !("domain" in details),
    session: !("expirationDate" in details),
  };
  delete cookie.url;
  jar = jar.filter((item) => !(
    item.name === cookie.name && item.domain === cookie.domain && item.path === cookie.path
  ));
  jar.push(cookie);
  return cookie;
};
globalThis.__scenarioResult = setTemporaryCookies([{
  name: "bootstrap",
  value: "temporary-bootstrap",
  domain: "vpn.example.test",
  path: "/",
  secure: true,
  expires: null,
  host_only: true,
}], "https://vpn.example.test")
  .then(() => ({ rejected: false, installedValues, jar }))
  .catch(() => ({ rejected: true, installedValues, jar }));
"""
    )

    assert result["rejected"] is True
    assert "temporary-bootstrap" not in result["installedValues"]
    assert {cookie["value"] for cookie in result["jar"]} == {
        "first-original",
        "second-original",
    }


def test_cookie_cleanup_continues_after_one_prior_cookie_cannot_be_restored():
    result = _run_background_scenario(
        r"""
let jar = [
  { name: "first", value: "temporary-first", domain: "vpn.example.test", path: "/" },
  { name: "second", value: "temporary-second", domain: "vpn.example.test", path: "/" },
];
chrome.cookies.getAll = async ({ name }) => jar.filter((cookie) => cookie.name === name);
chrome.cookies.remove = async ({ name }) => {
  const index = jar.findIndex((cookie) => cookie.name === name);
  return index < 0 ? null : jar.splice(index, 1)[0];
};
chrome.cookies.set = async (details) => {
  if (details.value === "original-second") throw new Error("synthetic restore failure");
  const cookie = {
    ...details,
    domain: details.domain || new URL(details.url).hostname,
    hostOnly: !("domain" in details),
  };
  delete cookie.url;
  jar.push(cookie);
  return cookie;
};
const temporary = [
  { name: "first", value: "temporary-first", path: "/", host_only: true },
  { name: "second", value: "temporary-second", path: "/", host_only: true },
];
const previous = [
  [{ name: "first", value: "original-first", domain: "vpn.example.test",
     path: "/", secure: true, httpOnly: true, sameSite: "strict",
     hostOnly: true, session: true, storeId: "0" }],
  [{ name: "second", value: "original-second", domain: "vpn.example.test",
     path: "/", secure: true, httpOnly: true, sameSite: "strict",
     hostOnly: true, session: true, storeId: "0" }],
];
globalThis.__scenarioResult = restoreCookies(
  temporary, previous, "https://vpn.example.test"
).then(() => ({ rejected: false, jar })).catch(() => ({ rejected: true, jar }));
"""
    )

    assert result["rejected"] is True
    assert {cookie["value"] for cookie in result["jar"]} == {"original-first"}


def test_readme_documents_the_narrow_privileged_installer():
    readme = (ROOT.parents[0] / "README.md").read_text()

    for required in (
        "macos/MerakiOpenConnect/MerakiOpenConnect.xcodeproj",
        "Sign to Run Locally",
        "Quit disconnects",
        "meraki-openconnect doctor --json",
        "meraki-openconnect privileged install",
        "Chrome Native Messaging",
    ):
        assert required in readme

    assert "meraki-openconnect privileged install" in readme
    assert "meraki-openconnect connect" in readme
    assert "meraki-openconnect disconnect" in readme
    assert "experimental-connect" not in readme
    assert "experimental-disconnect" not in readme
    assert "older `meraki-openconnect connect`" not in readme
    assert "does not authorize OpenConnect directly" in readme
    assert "visible Terminal" in readme
    assert "nonce-protected loopback callback" not in readme
