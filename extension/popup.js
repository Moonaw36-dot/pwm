"use strict";

const $ = (id) => document.getElementById(id);
const send = (message) => browser.runtime.sendMessage(message);

let tab = null;
let status = null;

function show(section) {
  for (const id of ["missing", "locked", "unlocked"]) $(id).hidden = id !== section;
  $("lock").hidden = section !== "unlocked";
}

function say(text, kind = "error") {
  const el = $("message");
  el.textContent = text || "";
  el.className = kind === "ok" ? "error ok" : "error";
}

function hostOf(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

function renderLocked() {
  show("locked");
  $("vault-line").textContent = status.vault_exists
    ? `Vault: ${status.vault_name}`
    : "No vault is known yet: enter its path below or open one in Aegis first.";
  $("path").value = status.vault_path || "";
  $("advanced").open = !status.vault_exists || status.needs_keyfile;
  $("password").focus();
}

function matchRow(match) {
  const row = document.createElement("div");
  row.className = "row";
  const who = document.createElement("div");
  who.className = "who";
  const name = document.createElement("b");
  name.textContent = match.label || hostOf(match.url);
  const user = document.createElement("span");
  user.className = "muted";
  user.textContent = match.username || "(no username)";
  who.append(name, user);

  const actions = document.createElement("div");
  actions.className = "actions";
  const fill = document.createElement("button");
  fill.className = "primary";
  fill.textContent = "Fill";
  fill.addEventListener("click", async () => {
    const reply = await send({ type: "fill", tabId: tab.id, id: match.id });
    if (reply.ok && reply.filled) window.close();
    else say(fillProblem(reply));
  });
  actions.append(fill);

  if (match.has_totp) {
    const totp = document.createElement("button");
    totp.textContent = "Code";
    totp.title = "Copy the one-time code";
    totp.addEventListener("click", async () => {
      const reply = await send({ type: "totp", tabId: tab.id, id: match.id, label: match.label, username: match.username });
      if (reply.ok && reply.totp) {
        await navigator.clipboard.writeText(reply.totp);
        // The popup closes soon; the background wipes the code if it's still there.
        send({ type: "clear-clipboard-later", text: reply.totp });
        say("One-time code copied.", "ok");
      } else say(reply.error || "Could not read the code.");
    });
    actions.append(totp);
  }
  row.append(who, actions);
  return row;
}

function fillProblem(reply) {
  if (reply.reason === "form_action_mismatch") return "This form sends its data to a different site, so Aegis did not fill it.";
  if (reply.reason === "no_password_field") return "No password field found on this page.";
  return reply.error || "Could not fill this page.";
}

async function renderUnlocked(settings) {
  show("unlocked");
  $("autofill").checked = settings.autofill;
  $("site-line").textContent = hostOf(tab.url);
  const reply = await send({ type: "search", url: tab.url, tabId: tab.id });
  const list = $("matches");
  list.replaceChildren();
  if (!reply.ok) {
    say(reply.error);
    return;
  }
  if (reply.matches.length === 0) {
    const none = document.createElement("p");
    none.className = "muted";
    none.textContent = /^https:|^http:\/\/(localhost|127\.0\.0\.1)/.test(tab.url)
      ? "No saved logins for this site."
      : "Logins are only offered on HTTPS pages.";
    list.append(none);
  }
  for (const match of reply.matches) list.append(matchRow(match));

  $("pending").hidden = !reply.pending;
  if (reply.pending) {
    $("pending-text").textContent = reply.pending.username
      ? `Save the login for ${reply.pending.username} on ${hostOf(reply.pending.url)}?`
      : `Save the password you just used on ${hostOf(reply.pending.url)}?`;
  }
}

async function refresh() {
  say("");
  const reply = await send({ type: "status" });
  if (!reply.ok) {
    if (reply.code === "host_unavailable") {
      show("missing");
      $("missing-detail").textContent = reply.error;
    } else {
      show("locked");
      say(reply.error);
    }
    return;
  }
  status = reply.status;
  if (status.unlocked) await renderUnlocked(reply.settings);
  else renderLocked();
}

$("unlock-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  say("");
  const password = $("password").value;
  if (!password) return say("Enter your master password.");
  const reply = await send({
    type: "unlock",
    password,
    path: $("path").value.trim() || undefined,
    keyfile: $("keyfile").value.trim() || undefined,
    tabId: tab.id,
  });
  $("password").value = "";
  if (!reply.ok) {
    if (reply.code === "keyfile_required") $("advanced").open = true;
    return say(reply.error);
  }
  await refresh();
});

$("lock").addEventListener("click", async () => {
  await send({ type: "lock" });
  await refresh();
});

$("autofill").addEventListener("change", (event) => {
  send({ type: "set-settings", settings: { autofill: event.target.checked } });
});

$("pending-save").addEventListener("click", async () => {
  const reply = await send({ type: "save-pending", tabId: tab.id, title: hostOf(tab.url) });
  if (reply.ok) {
    await refresh();
    say(reply.action === "updated" ? "Password updated." : "Login saved.", "ok");
  } else say(reply.error);
});

$("pending-dismiss").addEventListener("click", async () => {
  await send({ type: "dismiss-pending", tabId: tab.id });
  $("pending").hidden = true;
});

(async () => {
  [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  await refresh();
})();
