import { useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Shield, LogIn, AlertTriangle, Loader2, KeyRound, Mail } from "lucide-react";

import { AUTH_BASE, APP_BASE } from "../utils.js";
import { parseErrorMessage, splitIdentifier } from "../utils.js";


export default function Login() {
  const navigate = useNavigate();
  const [searchParams, _] = useSearchParams();

  const caller = decodeURI(searchParams.get("utm_source") || APP_BASE);

  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");

  const [status, setStatus] = useState({ type: "", message: "" });
  const [submitting, setSubmitting] = useState(false);

  async function onSubmit(e) {
    e.preventDefault();
    setStatus({ type: "", message: "" });

    const { email, telegram } = splitIdentifier(identifier);

    setSubmitting(true);
    try {
      const loginUrl = new URL('/login', AUTH_BASE);
      const res = await fetch(loginUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ email, telegram, password }),
      });

      const data = await res.json().catch(() => null);

      if (!res.ok) {
        const msg = parseErrorMessage(data);

        if (msg.toLowerCase().includes("pending verification")) {
          sessionStorage.setItem(
            "cerberus.verify.pending",
            JSON.stringify({
              purpose: "registration",
              email,
              telegram,
              channel: "email",
            })
          );
          navigate(
            `/verify?stage=code&purpose=registration&email=${encodeURIComponent(
              email
            )}&telegram=${encodeURIComponent(telegram)}`
          );
          return;
        }

        setStatus({ type: "error", message: msg });
        return;
      }

      setStatus({ type: "success", message: "Login successful." });

      // Redirect to caller after short delay.
	  setTimeout(() => {
		window.location.href = encodeURI(caller);
	  }, 1000);
    } catch {
      setStatus({ type: "error", message: "Network error. Please try again." });
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="min-h-screen bg-tesoro-black text-white flex items-center justify-center px-4 py-10">
      <div className="w-full max-w-md rounded-[2rem] border border-white/10 bg-white/5 backdrop-blur-xl shadow-2xl p-8">
        <div className="flex items-start gap-3 mb-6">
          <div className="p-3 rounded-2xl bg-white/10 border border-white/10">
            <Shield className="w-6 h-6 text-tesoro-green" />
          </div>
          <div>
            <h1 className="text-2xl font-bold font-display">Sign in</h1>
            <p className="text-sm text-white/70">Use your email or Telegram Chat ID.</p>
          </div>
        </div>

        {status.message ? (
          <div
            className={`mb-6 rounded-2xl border px-4 py-3 text-sm flex items-start gap-2 ${
              status.type === "success"
                ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-100"
                : "border-red-500/30 bg-red-500/10 text-red-100"
            }`}
          >
            <AlertTriangle className="w-5 h-5 mt-0.5" />
            <div>{status.message}</div>
          </div>
        ) : null}

        <form onSubmit={onSubmit} className="space-y-5">
          <div>
            <label className="block text-xs font-medium text-white/70 mb-1" htmlFor="identifier">
              Email or Telegram Chat ID
            </label>
            <div className="relative">
              <Mail className="w-4 h-4 text-white/50 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                id="identifier"
                value={identifier}
                onChange={(e) => setIdentifier(e.target.value)}
                required
                placeholder="name@example.com or 123456789"
                className="w-full pl-9 rounded-xl bg-white/5 border border-white/15 px-3 py-2 text-sm outline-none focus:border-tesoro-green"
                autoComplete="off"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-white/70 mb-1" htmlFor="password">
              Password
            </label>
            <div className="relative">
              <KeyRound className="w-4 h-4 text-white/50 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                id="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                type="password"
                className="w-full pl-9 rounded-xl bg-white/5 border border-white/15 px-3 py-2 text-sm outline-none focus:border-tesoro-green"
                autoComplete="off"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={submitting}
            className="w-full rounded-2xl bg-tesoro-green text-white font-semibold px-4 py-3 cursor-pointer hover:brightness-110 transition disabled:opacity-60 disabled:cursor-not-allowed flex items-center justify-center gap-2"
          >
            {submitting ? <Loader2 className="w-5 h-5 animate-spin" /> : <LogIn className="w-5 h-5" />}
            Sign in
          </button>

          <div className="flex items-center justify-between text-sm text-white/70">
            <Link className="text-tesoro-green hover:underline" to="/register">
              Create an account
            </Link>
            <Link className="text-tesoro-green hover:underline" to="/verify?purpose=reset">
              Forgot password?
            </Link>
          </div>
        </form>
      </div>
    </div>
  );
}
