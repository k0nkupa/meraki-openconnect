const status = document.getElementById("status");

chrome.runtime.sendMessage({
  type: "start-auth",
}).then((result) => {
  status.textContent = result?.ok
    ? "Authentication tab opened. Complete any required Entra steps there."
    : "Meraki OpenConnect authentication could not start.";
}).catch(() => {
  status.textContent = "Meraki OpenConnect authentication could not start.";
});
