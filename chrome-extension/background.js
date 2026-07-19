const NATIVE_HOST = "io.github.k0nkupa.meraki_openconnect";
const PROFILE_DIGEST = /^sha256:[0-9a-f]{64}$/;

function nativeRequest(port, message) {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      port.onMessage.removeListener(onMessage);
      port.onDisconnect.removeListener(onDisconnect);
    };
    const onMessage = (response) => {
      cleanup();
      resolve(response);
    };
    const onDisconnect = () => {
      cleanup();
      reject(new Error("native authentication bridge disconnected"));
    };
    port.onMessage.addListener(onMessage);
    port.onDisconnect.addListener(onDisconnect);
    port.postMessage(message);
  });
}

function validateGatewayOrigin(value) {
  const parsed = new URL(value);
  if (
    parsed.protocol !== "https:" ||
    parsed.origin !== value ||
    parsed.pathname !== "/" ||
    parsed.search ||
    parsed.hash ||
    parsed.username ||
    parsed.password ||
    parsed.port
  ) {
    throw new Error("invalid gateway permission receipt");
  }
  return value;
}

function validateHttpsUrl(value, expectedOrigin, allowQuery) {
  const parsed = new URL(value);
  if (
    parsed.protocol !== "https:" ||
    parsed.origin !== expectedOrigin ||
    parsed.username ||
    parsed.password ||
    parsed.hash ||
    (!allowQuery && parsed.search)
  ) {
    throw new Error("unexpected authentication URL");
  }
  return parsed.href;
}

function gatewayUrl(gatewayOrigin, path = "/") {
  return new URL(path, `${gatewayOrigin}/`).href;
}

function cookieDetails(cookie, gatewayOrigin) {
  const details = {
    url: gatewayUrl(gatewayOrigin, cookie.path || "/"),
    name: cookie.name,
    value: cookie.value,
    path: cookie.path || "/",
    secure: cookie.secure !== false,
  };
  const hostOnly = cookie.host_only === true || cookie.hostOnly === true;
  if (!hostOnly) details.domain = cookie.domain;
  const expirationDate = cookie.expirationDate ?? cookie.expires;
  if (cookie.session !== true && Number.isFinite(expirationDate)) {
    details.expirationDate = expirationDate;
  }
  const httpOnly = cookie.http_only ?? cookie.httpOnly;
  if (typeof httpOnly === "boolean") details.httpOnly = httpOnly;
  const sameSite = cookie.same_site ?? cookie.sameSite;
  if (typeof sameSite === "string") details.sameSite = sameSite;
  if (typeof cookie.storeId === "string") details.storeId = cookie.storeId;
  if (cookie.partitionKey && typeof cookie.partitionKey === "object") {
    details.partitionKey = cookie.partitionKey;
  }
  return details;
}

function cookieRemovalDetails(url, name, cookie) {
  const details = { url, name };
  if (typeof cookie?.storeId === "string") details.storeId = cookie.storeId;
  if (cookie?.partitionKey && typeof cookie.partitionKey === "object") {
    details.partitionKey = cookie.partitionKey;
  }
  return details;
}

function cookieVariantKey(cookie) {
  return JSON.stringify([
    cookie.domain,
    cookie.hostOnly,
    cookie.path,
    cookie.storeId,
    cookie.partitionKey || null,
  ]);
}

async function restoreCookieSnapshot(previous, gatewayOrigin) {
  const failures = [];
  for (const cookie of previous) {
    try {
      await chrome.cookies.set(cookieDetails(cookie, gatewayOrigin));
    } catch (error) {
      failures.push(error);
    }
  }
  if (failures.length) throw failures[0];
}

async function removeCookieVariants(url, name, rollbackOnFailure = false) {
  const previous = await chrome.cookies.getAll({ url, name });
  let remaining = previous;
  try {
    for (
      let attempt = 0;
      remaining.length && attempt < previous.length;
      attempt += 1
    ) {
      const before = remaining.map(cookieVariantKey).sort().join("\n");
      await chrome.cookies.remove(cookieRemovalDetails(url, name, remaining[0]));
      const next = await chrome.cookies.getAll({ url, name });
      const after = next.map(cookieVariantKey).sort().join("\n");
      if (after === before) throw new Error("cookie cleanup did not make progress");
      remaining = next;
    }
    if (remaining.length) throw new Error("cookie cleanup is incomplete");
    return previous;
  } catch (error) {
    if (rollbackOnFailure) {
      await restoreCookieSnapshot(previous, new URL(url).origin);
    }
    throw error;
  }
}

async function fetchBootstrap(port) {
  const response = await nativeRequest(port, { type: "bootstrap" });
  if (response?.type !== "bootstrap" || typeof response.bootstrap !== "object") {
    throw new Error("bootstrap rejected");
  }
  const bootstrap = response.bootstrap;
  const gatewayOrigin = validateGatewayOrigin(bootstrap.gatewayOrigin);
  const loginOrigin = validateGatewayOrigin(bootstrap.loginOrigin);
  if (!PROFILE_DIGEST.test(bootstrap.profileDigest)) {
    throw new Error("invalid profile permission receipt");
  }
  bootstrap.loginUrl = validateHttpsUrl(bootstrap.loginUrl, loginOrigin, true);
  bootstrap.finalUrl = validateHttpsUrl(bootstrap.finalUrl, gatewayOrigin, false);
  if (!Array.isArray(bootstrap.cookies) || typeof bootstrap.cookieName !== "string") {
    throw new Error("invalid bootstrap payload");
  }
  bootstrap.cookies = bootstrap.cookies.filter(
    (cookie) => cookie?.name !== bootstrap.cookieName,
  );
  const exactOrigin = `${gatewayOrigin}/*`;
  const granted = await chrome.permissions.contains({ origins: [exactOrigin] });
  if (!granted) throw new Error("gateway permission is missing");
  return bootstrap;
}

async function setTemporaryCookies(cookies, gatewayOrigin) {
  const previous = [];
  const applied = [];
  try {
    for (const cookie of cookies) {
      const targetUrl = gatewayUrl(gatewayOrigin, cookie.path || "/");
      previous.push(await removeCookieVariants(targetUrl, cookie.name, true));
      applied.push(cookie);
      await chrome.cookies.set(cookieDetails(cookie, gatewayOrigin));
    }
    return previous;
  } catch (error) {
    await restoreCookies(applied, previous, gatewayOrigin);
    throw error;
  }
}

async function restoreCookies(cookies, previous, gatewayOrigin) {
  const failures = [];
  for (let index = cookies.length - 1; index >= 0; index -= 1) {
    const temporary = cookies[index];
    const targetUrl = gatewayUrl(gatewayOrigin, temporary.path || "/");
    try {
      await removeCookieVariants(targetUrl, temporary.name);
    } catch (error) {
      failures.push(error);
      continue;
    }
    for (const cookie of previous[index] || []) {
      try {
        await chrome.cookies.set(cookieDetails(cookie, gatewayOrigin));
      } catch (error) {
        failures.push(error);
      }
    }
  }
  if (failures.length) throw failures[0];
}

function pause(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function waitForToken(finalUrl, cookieName) {
  for (let attempt = 0; attempt < 180; attempt += 1) {
    const cookie = await chrome.cookies.get({ url: finalUrl, name: cookieName });
    if (cookie?.value) return cookie.value;
    await pause(1000);
  }
  throw new Error("token timeout");
}

async function removeTokenCookie(bootstrap) {
  validateHttpsUrl(bootstrap.finalUrl, bootstrap.gatewayOrigin, false);
  if (typeof bootstrap.cookieName !== "string" || !bootstrap.cookieName) {
    throw new Error("unexpected token target");
  }
  await removeCookieVariants(bootstrap.finalUrl, bootstrap.cookieName);
}

async function cleanupAuthentication(bootstrap, cookiesSet, previous) {
  const failures = [];
  try {
    await removeTokenCookie(bootstrap);
  } catch (error) {
    failures.push(error);
  }
  if (cookiesSet) {
    try {
      await restoreCookies(bootstrap.cookies, previous, bootstrap.gatewayOrigin);
    } catch (error) {
      failures.push(error);
    }
  }
  if (failures.length) throw failures[0];
}

async function startAuthentication() {
  const native = chrome.runtime.connectNative(NATIVE_HOST);
  let bootstrap;
  let previous = [];
  let cookiesSet = false;
  let tab;
  try {
    bootstrap = await fetchBootstrap(native);
    previous = await setTemporaryCookies(
      bootstrap.cookies,
      bootstrap.gatewayOrigin,
    );
    cookiesSet = true;
    await removeTokenCookie(bootstrap);
    tab = await chrome.tabs.create({ url: bootstrap.loginUrl, active: true });
    const token = await waitForToken(bootstrap.finalUrl, bootstrap.cookieName);
    const response = await nativeRequest(native, { type: "token", token });
    if (response?.type !== "accepted") throw new Error("native token handoff rejected");
  } finally {
    if (tab?.id) await chrome.tabs.remove(tab.id).catch(() => undefined);
    try {
      if (bootstrap) {
        await cleanupAuthentication(bootstrap, cookiesSet, previous);
      }
    } finally {
      native.disconnect();
    }
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (
    message?.type !== "start-auth" ||
    sender.id !== chrome.runtime.id ||
    sender.url !== chrome.runtime.getURL("start.html")
  ) return false;
  startAuthentication()
    .then(() => sendResponse({ ok: true }))
    .catch(() => sendResponse({ ok: false }));
  return true;
});
