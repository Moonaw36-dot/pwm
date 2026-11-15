"use strict";
// Content script (isolated world): fills login forms, reports submitted
// logins, and relays WebAuthn calls from webauthn-page.js to the background.
// The page can only see the DOM and the events defined here; it never gets a
// handle to the extension APIs, and all origin checks happen in the background.

(() => {
  if (window.__aegisContent) return;
  Object.defineProperty(window, "__aegisContent", { value: true });

  // The manifest only injects into the top frame; stay inert if that changes.
  if (window !== window.top) return;
  const isTopFrame = true;
  const getAttr = Element.prototype.getAttribute;
  const formElements = Object.getOwnPropertyDescriptor(HTMLFormElement.prototype, "elements").get;
  // Lets the page-world script know the relay is alive before it takes over
  // navigator.credentials (otherwise it leaves the browser's own handling).
  function markBridge() {
    if (!document.documentElement) return false;
    document.documentElement.setAttribute("data-aegis-bridge", "1");
    return true;
  }
  if (!markBridge()) {
    const waiter = new MutationObserver(() => markBridge() && waiter.disconnect());
    waiter.observe(document, { childList: true });
  }

  // ------------------------------------------------------------ form helpers

  function isUsable(input) {
    if (input.disabled || input.readOnly || input.type === "hidden") return false;
    const style = getComputedStyle(input);
    if (style.visibility === "hidden" || style.display === "none") return false;
    const rect = input.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  }

  function passwordFields() {
    return [...document.querySelectorAll('input[type="password"]')].filter(isUsable);
  }

  const TEXT_TYPES = new Set(["", "text", "email", "tel", "url", "search"]);

  function usernameFieldFor(passwordField) {
    const scope = passwordField.form ? [...passwordField.form.elements] : [...document.querySelectorAll("input")];
    let best = null;
    for (const el of scope) {
      if (!(el instanceof HTMLInputElement) || el === passwordField) continue;
      if (!TEXT_TYPES.has((el.getAttribute("type") || "").toLowerCase()) || !isUsable(el)) continue;
      if (el.compareDocumentPosition(passwordField) & Node.DOCUMENT_POSITION_FOLLOWING) best = el;
    }
    return best;
  }

  function stripWww(host) {
    return host.replace(/^www\./, "");
  }

  const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

  // The target may be the page's own host or one of its subdomains, not a
  // parent or sibling.
  function related(target) {
    const a = stripWww(target.hostname);
    const b = stripWww(location.hostname);
    if (LOOPBACK.has(b)) return a === b && target.port === location.port;
    return a === b || a.endsWith("." + b);
  }

  function actionBlocked(value) {
    if (value === null || value.trim() === "") return false; // posts back to the page
    try {
      const target = new URL(value, location.href);
      if (target.protocol !== "https:" && !(target.protocol === "http:" && LOOPBACK.has(target.hostname))) return true;
      return !related(target);
    } catch {
      return true;
    }
  }

  // A form that posts to an unrelated site is a classic credential-theft
  // trick, so it never gets an automatic fill. Read the attributes, not the
  // properties: an input named "action" would shadow form.action.
  function formTargetsOtherSite(passwordField) {
    const form = passwordField.form;
    if (!form) return false;
    if (actionBlocked(Reflect.apply(getAttr, form, ["action"]))) return true;
    return [...formElements.call(form)].some((el) => {
      const formaction = Reflect.apply(getAttr, el, ["formaction"]);
      return formaction !== null && actionBlocked(formaction);
    });
  }

  function setValue(input, value) {
    input.focus({ preventScroll: true });
    input.value = value;
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function fillFields(creds, { manual }) {
    const fields = passwordFields();
    const target = fields.find((f) => !/new-password/.test(f.autocomplete)) || (manual ? fields[0] : null);
    if (!target) return { filled: false, reason: "no_password_field" };
    // Without a form nothing says where the password goes; only fill on request.
    if (!target.form && !manual) return { filled: false, reason: "no_form" };
    if (formTargetsOtherSite(target)) return { filled: false, reason: "form_action_mismatch" };

    const username = usernameFieldFor(target);
    if (username && creds.username) setValue(username, creds.username);
    setValue(target, creds.password);
    filled.add(target);
    return { filled: true };
  }

  // ------------------------------------------------------------- autofill

  const filled = new WeakSet();
  let asked = false;
  let attempts = 0;

  async function tryAutofill() {
    if (!isTopFrame || asked) return;
    const fields = passwordFields().filter((f) => !filled.has(f) && !/new-password/.test(f.autocomplete));
    if (fields.length === 0) return;
    asked = true;
    let reply;
    try {
      reply = await browser.runtime.sendMessage({ type: "autofill-query" });
    } catch {
      asked = false;
      return;
    }
    if (reply && reply.status === "fill") {
      fillFields({ username: reply.username, password: reply.password }, { manual: false });
    } else if (reply && (reply.status === "locked" || reply.status === "error")) {
      // The user may unlock later; allow another attempt on the next change.
      asked = false;
      attempts += 4;
    }
  }

  let debounce = null;
  function scheduleAutofill() {
    if (!isTopFrame || attempts > 20) return;
    clearTimeout(debounce);
    debounce = setTimeout(() => {
      attempts += 1;
      tryAutofill();
    }, 400);
  }

  new MutationObserver(scheduleAutofill).observe(document, { childList: true, subtree: true });
  document.addEventListener("DOMContentLoaded", scheduleAutofill);
  window.addEventListener("load", scheduleAutofill);

  browser.runtime.onMessage.addListener((message) => {
    if (message && message.type === "fill" && isTopFrame) {
      // The background read this URL from the tab; refuse if we've since navigated.
      let same = false;
      try {
        same = new URL(message.url).origin === location.origin;
      } catch {}
      if (!same) return Promise.resolve({ filled: false, reason: "page_changed" });
      return Promise.resolve(fillFields(message, { manual: true }));
    }
    return undefined;
  });

  // ------------------------------------------------------ submitted logins

  let lastReport = 0;
  function reportLogin(passwordField) {
    const password = passwordField.value;
    if (!password || !isTopFrame || Date.now() - lastReport < 1000) return;
    lastReport = Date.now();
    const usernameField = usernameFieldFor(passwordField);
    browser.runtime
      .sendMessage({
        type: "login-submitted",
        username: usernameField ? usernameField.value : "",
        password,
      })
      .catch(() => {});
  }

  function activePasswordField(root) {
    return [...(root || document).querySelectorAll('input[type="password"]')].find((f) => f.value);
  }

  document.addEventListener(
    "submit",
    (event) => {
      if (!event.isTrusted) return;
      const field = activePasswordField(event.target);
      if (field) reportLogin(field);
    },
    true,
  );

  document.addEventListener(
    "keydown",
    (event) => {
      if (event.isTrusted && event.key === "Enter" && event.target instanceof HTMLInputElement && event.target.type === "password") {
        reportLogin(event.target);
      }
    },
    true,
  );

  document.addEventListener(
    "click",
    (event) => {
      if (!event.isTrusted || !(event.target instanceof Element)) return;
      // Only controls that submit a form: not "show password" toggles.
      const button = event.target.closest('button:not([type]), button[type="submit"], input[type="submit"]');
      if (!button) return;
      const field = activePasswordField(button.form || undefined);
      if (field) reportLogin(field);
    },
    true,
  );

  // ------------------------------------------------------------- passkeys

  window.addEventListener("aegis:req", async (event) => {
    // Read the activation state synchronously, while the page's click is live.
    const active = !!(navigator.userActivation && navigator.userActivation.isActive);
    let request;
    try {
      if (typeof event.detail !== "string" || event.detail.length > 64 * 1024) return;
      request = JSON.parse(event.detail);
    } catch {
      return;
    }
    if (!request || (request.type !== "create" && request.type !== "get")) return;

    let reply;
    try {
      reply = active
        ? await browser.runtime.sendMessage({
            type: `passkey-${request.type}`,
            request: request.payload,
            userActivation: true,
          })
        : { fallback: true };
    } catch {
      reply = { fallback: true };
    }
    window.dispatchEvent(
      new CustomEvent("aegis:res", { detail: JSON.stringify({ id: request.id, ...(reply || { fallback: true }) }) }),
    );
  });
})();
