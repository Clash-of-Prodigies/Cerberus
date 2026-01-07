const AUTH_BASE = new URL('auth', import.meta.env.VITE_API_URL);
const APP_BASE = new URL('home', import.meta.env.VITE_APP_URL);

function parseErrorMessage(payload) {
  if (!payload) return "Request failed.";
  if (typeof payload === "string") return payload;
  if (Array.isArray(payload)) return payload.join(", ");
  if (typeof payload.message === "string") return payload.message;
  if (Array.isArray(payload.message)) return payload.message.join(", ");
  return "Request failed.";
}

function splitIdentifier(identifier) {
  const v = String(identifier || "").trim();
  if (!v) return { email: "", telegram: "" };
  if (v.includes("@")) return { email: v, telegram: "" };
  return { email: "", telegram: v };
}

export { AUTH_BASE, APP_BASE };

export { parseErrorMessage, splitIdentifier };