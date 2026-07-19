const NATIVE_HOST = "io.github.k0nkupa.meraki_openconnect";
const PROFILE_DIGEST = /^sha256:[0-9a-f]{64}$/;
const grantButton = document.getElementById("grant-permission");
const originLabel = document.getElementById("gateway-origin");
const status = document.getElementById("status");
const native = chrome.runtime.connectNative(NATIVE_HOST);
let gatewayOrigin;
let profileDigest;

function nativeRequest(message) {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      native.onMessage.removeListener(onMessage);
      native.onDisconnect.removeListener(onDisconnect);
    };
    const onMessage = (response) => {
      cleanup();
      resolve(response);
    };
    const onDisconnect = () => {
      cleanup();
      reject(new Error("native setup bridge disconnected"));
    };
    native.onMessage.addListener(onMessage);
    native.onDisconnect.addListener(onDisconnect);
    native.postMessage(message);
  });
}

function validateBootstrap(response) {
  const parsed = new URL(response?.gatewayOrigin);
  if (
    response?.type !== "setup-bootstrap" ||
    parsed.protocol !== "https:" ||
    parsed.origin !== response.gatewayOrigin ||
    parsed.pathname !== "/" ||
    parsed.search ||
    parsed.hash ||
    parsed.port ||
    !PROFILE_DIGEST.test(response.profileDigest)
  ) {
    throw new Error("invalid setup bootstrap");
  }
  return response;
}

nativeRequest({ type: "setup-bootstrap" })
  .then(validateBootstrap)
  .then((bootstrap) => {
    gatewayOrigin = bootstrap.gatewayOrigin;
    profileDigest = bootstrap.profileDigest;
    originLabel.textContent = gatewayOrigin;
    grantButton.disabled = false;
  })
  .catch(() => {
    status.textContent = "Meraki OpenConnect setup could not start.";
    native.disconnect();
  });

grantButton.addEventListener("click", async () => {
  grantButton.disabled = true;
  const exactOrigin = `${gatewayOrigin}/*`;
  let granted = false;
  try {
    granted = await chrome.permissions.request({ origins: [exactOrigin] });
    const response = await nativeRequest({
      type: "setup-result",
      gatewayOrigin,
      profileDigest,
      granted,
    });
    if (response?.type !== "accepted") throw new Error("setup result rejected");
    status.textContent = granted
      ? "Gateway permission granted. Return to Meraki OpenConnect."
      : "Gateway permission was not granted.";
  } catch (_error) {
    status.textContent = "Meraki OpenConnect setup could not finish.";
  } finally {
    native.disconnect();
  }
});
