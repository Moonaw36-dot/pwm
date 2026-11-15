"use strict";

const $ = (id) => document.getElementById(id);
const send = (message) => browser.runtime.sendMessage(message);
const promptId = Number(new URLSearchParams(location.search).get("id"));

let decided = false;

function say(text) {
  $("message").textContent = text || "";
}

function decide(decision, credentialId) {
  if (decided) return;
  decided = true;
  send({ type: "prompt-decision", id: promptId, decision, credentialId });
}

function showOnly(...ids) {
  for (const id of ["locked", "create", "get", "actions"]) $(id).hidden = !ids.includes(id);
}

function candidateRow(candidate) {
  const row = document.createElement("div");
  row.className = "row";
  const who = document.createElement("div");
  who.className = "who";
  const name = document.createElement("b");
  name.textContent = candidate.user_display_name || candidate.user_name;
  const user = document.createElement("span");
  user.className = "muted";
  user.textContent = candidate.user_name;
  who.append(name, user);
  const choose = document.createElement("button");
  choose.className = "primary";
  choose.textContent = "Sign in";
  choose.addEventListener("click", () => decide("approve", candidate.credential_id));
  row.append(who, choose);
  return row;
}

async function render() {
  say("");
  const info = await send({ type: "prompt-info", id: promptId });
  if (!info.ok) {
    showOnly("actions");
    $("fallback").hidden = true;
    return say(info.error || "This request is no longer active.");
  }
  const { details, locked, status } = info;

  if (locked) {
    showOnly("locked", "actions");
    $("path").value = status.vault_path || "";
    $("advanced").open = !status.vault_exists || status.needs_keyfile;
    $("password").focus();
    return;
  }

  if (details.kind === "create") {
    showOnly("create", "actions");
    // The domain comes from the browser; the display name is chosen by the
    // page, so it is shown only as a secondary detail.
    $("create-site").textContent = details.rpId;
    const showName = details.rpName && details.rpName !== details.rpId;
    $("create-name-label").hidden = !showName;
    $("create-name").hidden = !showName;
    $("create-name").textContent = showName ? details.rpName : "";
    $("create-replaces").hidden = !details.replaces;
    $("create-user").textContent = details.user.displayName && details.user.displayName !== details.user.name
      ? `${details.user.displayName} (${details.user.name})`
      : details.user.name;
    return;
  }

  showOnly("get", "actions");
  $("get-site").textContent = details.rpId;
  const list = $("candidates");
  list.replaceChildren();
  if (details.candidates.length === 0) {
    const none = document.createElement("p");
    none.className = "muted";
    none.textContent = "Aegis has no passkey for this site.";
    list.append(none);
  }
  for (const candidate of details.candidates) list.append(candidateRow(candidate));
}

$("unlock-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const password = $("password").value;
  if (!password) return say("Enter your master password.");
  const reply = await send({
    type: "unlock",
    password,
    path: $("path").value.trim() || undefined,
    keyfile: $("keyfile").value.trim() || undefined,
  });
  $("password").value = "";
  if (!reply.ok) {
    if (reply.code === "keyfile_required") $("advanced").open = true;
    return say(reply.error);
  }
  await render();
});

$("create-ok").addEventListener("click", () => decide("approve"));
$("fallback").addEventListener("click", () => decide("fallback"));
$("cancel").addEventListener("click", () => decide("cancel"));
// Closing the window counts as cancel; the background handles windows.onRemoved.

render();
