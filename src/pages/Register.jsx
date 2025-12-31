import React, { useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import {
  Shield,
  UserPlus,
  Mail,
  MessageCircle,
  KeyRound,
  AlertTriangle,
  Loader2,
} from "lucide-react";

function normalizeBase(base, defaultPath = "/auth") {
  if (base == null) return defaultPath;
  const trimmed = String(base).trim();
  if (!trimmed) return defaultPath;
  return trimmed.endsWith("/") ? trimmed.slice(0, -1) : trimmed;
}

function parseErrorMessage(payload) {
  if (!payload) return "Request failed.";
  if (typeof payload === "string") return payload;
  if (Array.isArray(payload)) return payload.join(", ");
  if (typeof payload.message === "string") return payload.message;
  if (Array.isArray(payload.message)) return payload.message.join(", ");
  return "Request failed.";
}

export default function Register() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();

  const AUTH_BASE = useMemo(
    () => normalizeBase(import.meta.env.VITE_BACKEND_URL),
    []
  );

  const formatReferrer = (ref) => {
    if (!ref) return "AB6 7XY";
    const trimmed = ref.trim().toUpperCase();
    if (trimmed.length <= 3) return trimmed;
    return `${trimmed.slice(0, -3)} ${trimmed.slice(-3)}`;
  }

  const [status, setStatus] = useState({ type: "", message: "" });
  const [submitting, setSubmitting] = useState(false);

  const [form, setForm] = useState({
    fullName: "",
    username: "",
    email: "",
    telegram: "",
    age: "",
    referrer: formatReferrer(searchParams.get("ref") || "ab67xy"),
    institution: "",
    password: "",
    confirmPassword: "",
    channel: "email",
    agreed: false,
  });

  function setField(name, value) {
    setForm((p) => ({ ...p, [name]: value }));
  }

  function onConfirmPasswordChange(nextConfirm) {
    setField("confirmPassword", nextConfirm);
  }

  async function onSubmit(e) {
    e.preventDefault();
    setStatus({ type: "", message: "" });

    if (form.password !== form.confirmPassword) {
      setStatus({ type: "error", message: "Passwords do not match." });
      return;
    }

    setSubmitting(true);
    try {
      const payload = {
        "full-name": form.fullName,
        username: form.username,
        email: form.email,
        telegram: form.telegram,
        age: Number(form.age),
        referrer: form.referrer,
        institution: form.institution,
        password: form.password,
        "confirm-password": form.confirmPassword,
        agreed: !!form.agreed,
      };

      const res = await fetch(`${AUTH_BASE}/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const data = await res.json().catch(() => null);

      if (!res.ok) {
        const msg = parseErrorMessage(data);

        // If user already exists but is pending, backend re-sends OTP. :contentReference[oaicite:4]{index=4}
        if (msg.toLowerCase().includes("pending verification")) {
          sessionStorage.setItem(
            "cerberus.verify.pending",
            JSON.stringify({
              purpose: "registration",
              email: form.email,
              telegram: form.telegram,
            })
          );
          navigate(
            `/verify?stage=code&purpose=registration&channel=${encodeURIComponent(
              form.channel
            )}&email=${encodeURIComponent(form.email)}&telegram=${encodeURIComponent(
              form.telegram
            )}`
          );
          return;
        }

        setStatus({ type: "error", message: msg });
        return;
      }

      setStatus({ type: "success", message: "Registration successful. Check for your verification code." });

      sessionStorage.setItem(
        "cerberus.verify.pending",
        JSON.stringify({
          purpose: "registration",
          email: form.email,
        })
      );

      navigate(
        `/verify?stage=code&purpose=registration&email=${encodeURIComponent(form.email)}`
      );
    } catch (err) {
      setStatus({
        type: "error",
        message: `Network error. ${err.message} Please try again.`,
      });
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="min-h-screen bg-tesoro-black text-white flex items-center justify-center px-4 py-10">
      <div className="w-full max-w-xl rounded-[2rem] border border-white/10 bg-white/5 backdrop-blur-xl shadow-2xl p-8">
        <div className="flex items-start gap-3 mb-6">
          <div className="p-3 rounded-2xl bg-white/10 border border-white/10">
            <Shield className="w-6 h-6 text-tesoro-green" />
          </div>
          <div>
            <h1 className="text-2xl font-bold font-display">Create your account</h1>
            <p className="text-sm text-white/70">
              Register for Prodigy services, then verify your account.
            </p>
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
            {status.type === "success" ? (
              <UserPlus className="w-5 h-5 mt-0.5" />
            ) : (
              <AlertTriangle className="w-5 h-5 mt-0.5" />
            )}
            <div>{status.message}</div>
          </div>
        ) : null}

        <form onSubmit={onSubmit} className="space-y-5">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-white/70 mb-1" htmlFor="fullName">
                Full Name
              </label>
              <input
                id="fullName"
                value={form.fullName}
                onChange={(e) => setField("fullName", e.target.value)}
                required
                placeholder="Last First"
                className="w-full rounded-xl bg-white/5 border border-white/15 px-3 py-2 text-sm outline-none focus:border-tesoro-green"
                pattern="[A-Za-z]+(?:-[A-Za-z]+)*\s+[A-Za-z]+"
                title="Please enter a first and last name."
                autoComplete="off"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-white/70 mb-1" htmlFor="username">
                Username
              </label>
              <input
                id="username"
                value={form.username}
                onChange={(e) => setField("username", e.target.value)}
                required
                placeholder="yourname"
                className="w-full rounded-xl bg-white/5 border border-white/15 px-3 py-2 text-sm outline-none focus:border-tesoro-green"
                pattern="[A-Za-z0-9_ .\\-]{5,15}"
                title="5 to 15 characters. Letters, numbers, underscore, space, dot, or hyphen."
                autoComplete="off"
              />
            </div>

            <div className="sm:col-span-2">
              <label className="text-xs font-medium text-white/70 mb-1" htmlFor="email">
                Email
              </label>
              <div className="relative">
                <Mail className="w-4 h-4 text-white/50 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  id="email"
                  value={form.email}
                  onChange={(e) => setField("email", e.target.value)}
                  required
                  type="email"
                  placeholder="name@example.com"
                  className="w-full pl-9 rounded-xl bg-white/5 border border-white/15 px-3 py-2 text-sm outline-none focus:border-tesoro-green"
                  pattern="[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
                  title="Please enter a valid email address."
                  autoComplete="off"
                />
              </div>
            </div>

			<div>
              <label className="block text-xs font-medium text-white/70 mb-1" htmlFor="age">
                Age
              </label>
              <input
                id="age"
                value={form.age}
                onChange={(e) => setField("age", e.target.value)}
                required
                type="number"
                min={10}
                max={25}
                className="w-full rounded-xl bg-white/5 border border-white/15 px-3 py-2 text-sm outline-none focus:border-tesoro-green"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-white/70 mb-1" htmlFor="referrer">
                Referral Code
              </label>
              <input
                id="referrer"
                value={form.referrer}
                onChange={(e) => setField("referrer", e.target.value.toUpperCase())}
                required
                placeholder="AB6 7XY"
                className="w-full rounded-xl bg-white/5 border border-white/15 px-3 py-2 text-sm outline-none focus:border-tesoro-green"
                pattern="[A-Z]{1,2}[0-9][0-9A-Z]?\s[0-9][A-Z]{2}"
                title="Please enter a valid referral code."
                autoComplete="off"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-white/70 mb-1" htmlFor="password">
                Password
              </label>
              <div className="relative">
                <KeyRound className="w-4 h-4 text-white/50 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  id="password"
                  value={form.password}
                  onChange={(e) => setField("password", e.target.value)}
                  required
                  type="password"
                  className="w-full pl-9 rounded-xl bg-white/5 border border-white/15 px-3 py-2 text-sm outline-none focus:border-tesoro-green"
                  pattern="(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}"
                  title="At least 8 characters with uppercase, lowercase, a number, and a symbol."
                  autoComplete="off"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-white/70 mb-1" htmlFor="confirmPassword">
                Confirm Password
              </label>
              <input
                id="confirmPassword"
                value={form.confirmPassword}
                onChange={(e) => onConfirmPasswordChange(e.target.value)}
                required
                type="password"
                className="w-full rounded-xl bg-white/5 border border-white/15 px-3 py-2 text-sm outline-none focus:border-tesoro-green"
                autoComplete="off"
              />
            </div>

			<div className="sm:col-span-2">
              <label className="block text-xs font-medium text-white/70 mb-1" htmlFor="institution">
                Name of Institution
              </label>
              <input
                id="institution"
                value={form.institution}
                onChange={(e) => setField("institution", e.target.value)}
                required
                placeholder="School name"
                className="w-full rounded-xl bg-white/5 border border-white/15 px-3 py-2 text-sm outline-none focus:border-tesoro-green"
                autoComplete="off"
              />
            </div>

            <div className="sm:col-span-2">
              <label className="flex items-start gap-2 text-sm text-white/80">
                <input
                  type="checkbox"
                  checked={form.agreed}
                  onChange={(e) => setField("agreed", e.target.checked)}
                  required
                  className="mt-1"
                />
                <span>
                  I agree to the&nbsp;
				  <Link className="text-tesoro-green hover:underline" to={import.meta.env.VITE_TERMS_URL}>Terms of Service</Link>&nbsp;
				  and <Link className="text-tesoro-green hover:underline" to={import.meta.env.VITE_PRIVACY_URL}>Privacy Policy</Link>.
                </span>
              </label>
            </div>
          </div>

          <button
            type="submit"
            disabled={submitting}
            className="w-full rounded-2xl bg-tesoro-green text-white font-semibold px-4 py-3 cursor-pointer hover:brightness-110 transition disabled:opacity-60 disabled:cursor-not-allowed flex items-center justify-center gap-2"
          >
            {submitting ? <Loader2 className="w-5 h-5 animate-spin" /> : <UserPlus className="w-5 h-5" />}
            Create account
          </button>

          <div className="text-sm text-white/70 flex items-center justify-between">
            <span>Already have an account?&nbsp;
				<Link className="text-tesoro-green hover:underline" to="/login">Sign in</Link>
            </span>
			<Link className="text-tesoro-green hover:underline" to="/verify?purpose=reset">
			  Forgot password?
			</Link>
          </div>
        </form>
      </div>
    </div>
  );
}
