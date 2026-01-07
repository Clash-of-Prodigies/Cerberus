import { useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Shield, Mail, MessageCircle, ArrowRight, KeyRound, AlertTriangle, } from "lucide-react";
import { Loader2 } from "lucide-react";

import { AUTH_BASE, } from "../utils.js";
import { parseErrorMessage, splitIdentifier } from "../utils.js";

function goto(nextStage, overrides = {}, searchParams, purpose, setSearchParams) {
  const next = new URLSearchParams(searchParams);
  next.set("stage", nextStage);
  next.set("purpose", purpose);
  if (overrides.channel) next.set("channel", overrides.channel);
  if (overrides.email) next.set("email", overrides.email);
  if (overrides.telegram) next.set("telegram", overrides.telegram);
  setSearchParams(next);
}

async function sendOtpForReset({ email, telegram, channelChoice, }, verifyUrl) {
  const res = await fetch(verifyUrl, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, telegram, channel: channelChoice, purpose: "reset",}),
  });
  const data = await res.json().catch(() => null);
  if (!res.ok) throw new Error(parseErrorMessage(data));
  return data;
}

async function resendRegistrationOtp({ email, telegram, }, loginUrl) {
  const res = await fetch(loginUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email,
        telegram,
        password: "placeholder",
      }),
    });
    const data = await res.json().catch(() => null);
    if (res.ok) return { ok: true, message: "You are already active. You can sign in." };

    const msg = parseErrorMessage(data);
    if (msg.toLowerCase().includes("pending verification")) {
      return { ok: true, message: "A new verification code was sent." };
    }
    throw new Error(msg);
  }

async function onMethodSubmit(e, {purpose, channel, identifier}, verifyUrl, goto, searchParams, setSearchParams, setStatus, setSubmitting) {
  e.preventDefault();
  setStatus({ type: "", message: "" });

  const { email, telegram } = splitIdentifier(identifier);
  if (!email && !telegram) {
    setStatus({ type: "error", message: "Provide an email or Telegram Chat ID." });
    return;
  }

  setSubmitting(true);
  try {
    if (purpose === "reset") {
      await sendOtpForReset({ email, telegram, channelChoice: channel }, verifyUrl);
      setStatus({ type: "success", message: "OTP sent. Enter the code to continue." });
    }
    else {
      setStatus({
        type: "info",
        message: "If you just registered, your code was already sent. Enter it to verify.",
      });
    }

    sessionStorage.setItem("cerberus.verify.pending",
      JSON.stringify({ purpose, email, telegram, channel })
    );

    goto("code", { email, telegram, channel }, searchParams, purpose, setSearchParams);
    }
    catch (err) {
      setStatus({ type: "error", message: err?.message || "Request failed." });
    }
    finally { setSubmitting(false); }
}

async function onCodeSubmit(e, { purpose, channel, identifier, code, newPassword, confirmPassword }, verifyUrl, navigate, setStatus, setSubmitting) {
  e.preventDefault();
  setStatus({ type: "", message: "" });

  const { email, telegram } = splitIdentifier(identifier);
  if (!email && !telegram) {
    setStatus({ type: "error", message: "Provide an email or Telegram Chat ID." });
    return;
  }

  if (!/^\d{6}$/.test(code.trim())) {
    setStatus({ type: "error", message: "Enter the 6-digit code." });
    return;
  }

  if (purpose === "reset") {
    if (newPassword !== confirmPassword) {
      setStatus({ type: "error", message: "Passwords do not match." });
      return;
    }
    if (!newPassword) {
      setStatus({ type: "error", message: "Enter a new password." });
      return;
    }
  }

  setSubmitting(true);
  try {
    const payload = { email, telegram, channel, code: code.trim(), purpose, };
    if (purpose === "reset") {
      payload.password = newPassword;
      payload.confirm_password = confirmPassword;
    }

    const res = await fetch(verifyUrl, {
      method: "POST", headers: { "Content-Type":"application/json" }, body: JSON.stringify(payload),
    });

    const data = await res.json().catch(() => null);
    if (!res.ok) { throw new Error(parseErrorMessage(data)); }

    if (purpose === "reset") {
      setStatus({ type: "success", message: "Password reset successful. You can sign in now." });
      sessionStorage.removeItem("cerberus.verify.pending");
      navigate("/login");
    }
    else {
      setStatus({ type: "success", message: "Verification successful. You can sign in now." });
      sessionStorage.removeItem("cerberus.verify.pending");
      navigate("/login");
    }
  }
  catch (err) { setStatus({ type: "error", message: err?.message || "Verification failed." }); }
  finally { setSubmitting(false); }
}

async function onResendClick(setStatus, setSubmitting, { purpose, channel, identifier }, verifyUrl, loginUrl) {
  setStatus({ type: "", message: "" });
  const { email, telegram } = splitIdentifier(identifier);
  if (!email && !telegram) {
    setStatus({ type: "error", message: "Provide an email or Telegram Chat ID first." });
    return;
  }

  setSubmitting(true);
  try {
    if (purpose === "reset") {
      await sendOtpForReset({ email, telegram, channelChoice: channel }, verifyUrl);
      setStatus({ type: "success", message: "OTP re-sent." });
    }
    else {
      const out = await resendRegistrationOtp({ email, telegram }, loginUrl);
      setStatus({ type: "success", message: out.message });
    }
  }
  catch (err) { setStatus({ type: "error", message: err?.message || "Resend failed." }); }
  finally { setSubmitting(false); }
}

export default function Verify() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();

  const obj = JSON.parse(sessionStorage.getItem("cerberus.verify.pending")) || {};

  const stage = (searchParams.get("stage") || "method").toLowerCase();
  const purpose = (searchParams.get("purpose") || "registration").toLowerCase();
  const urlEmail = searchParams.get("email") || obj.email || "";
  const urlTelegram = searchParams.get("telegram") || obj.telegram || "";
  const urlChannel = (searchParams.get("channel") || obj.channel || "").toLowerCase();

  const [status, setStatus] = useState({ type: "", message: "" });
  const [submitting, setSubmitting] = useState(false);

  const [identifier, setIdentifier] = useState(urlEmail || urlTelegram);
  const [channel, setChannel] = useState(urlChannel ||
    (urlEmail ? "email" : urlTelegram ? "telegram" : "email"));

  const [code, setCode] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const verifyUrl = new URL('verify', AUTH_BASE);
  const loginUrl = new URL('login', AUTH_BASE);
  const isMethodStage = stage !== "code";

  return (
    <div className="min-h-screen bg-tesoro-black text-white flex items-center justify-center px-4 py-10">
      <div className="w-full max-w-md rounded-[2rem] border border-white/10 bg-white/5 backdrop-blur-xl shadow-2xl p-8">
        <div className="flex items-start gap-3 mb-6">
          <div className="p-3 rounded-2xl bg-white/10 border border-white/10">
            <Shield className="w-6 h-6 text-tesoro-green" />
          </div>
          <div>
            <h1 className="text-2xl font-bold font-display">
              {purpose === "reset" ? "Reset password" : "Verify account"}
            </h1>
            <p className="text-sm text-white/70">
              {isMethodStage ? "Choose a verification method." : "Enter your verification code."}
            </p>
          </div>
        </div>

        {status.message ? (
          <div
            className={`mb-6 rounded-2xl border px-4 py-3 text-sm flex items-start gap-2 ${
              status.type === "success"
                ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-100"
                : status.type === "info"
                ? "border-white/15 bg-white/5 text-white/80"
                : "border-red-500/30 bg-red-500/10 text-red-100"
            }`}
          >
            {status.type === "error" ? (
              <AlertTriangle className="w-5 h-5 mt-0.5" />
            ) : (
              <KeyRound className="w-5 h-5 mt-0.5" />
            )}
            <div>{status.message}</div>
          </div>
        ) : null}

        {isMethodStage ? (
          <form onSubmit={(e) => onMethodSubmit(e, {purpose, channel, identifier}, verifyUrl, goto, searchParams, setSearchParams, setStatus, setSubmitting)} className="space-y-5">
            <div>
              <label className="block text-xs font-medium text-white/70 mb-1" htmlFor="identifier">
                Email or Telegram Chat ID
              </label>
              <input id="identifier" required value={identifier} autoComplete="off"
                onChange={(e) => setIdentifier(e.target.value)} placeholder="name@example.com or 123456789"
                className="w-full rounded-xl bg-white/5 border border-white/15 px-3 py-2 text-sm outline-none focus:border-tesoro-green"
              />
            </div>

            <div>
              <p className="text-xs font-medium text-white/70 mb-2">Verification channel</p>
              <div className="flex flex-col gap-3">
                <label className="flex items-center gap-2 rounded-xl border border-white/10 bg-white/5 px-3 py-2">
                  <input type="radio" name="channel" value="email"
                    checked={channel === "email"} onChange={() => setChannel("email")}
                  />
                  <Mail className="w-4 h-4 text-white/60" />
                  <span className="text-sm">Email</span>
                </label>
                <label className="flex items-center gap-2 rounded-xl border border-white/10 bg-white/5 px-3 py-2">
                  <input type="radio" name="channel" value="telegram"
                    checked={channel === "telegram"} onChange={() => setChannel("telegram")}
                  />
                  <MessageCircle className="w-4 h-4 text-white/60" />
                  <span className="text-sm">Telegram</span>
                </label>
              </div>
              <p className="text-xs text-white/50 mt-2">
                For password resets, selecting a method will send a code. For registration verification, if you already registered, your code was sent during registration.
              </p>
            </div>

            <button type="submit" disabled={submitting}
              className="w-full rounded-2xl bg-tesoro-green text-white cursor-pointer font-semibold px-4 py-3 hover:brightness-110 transition disabled:opacity-60 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            >
              {submitting ? <Loader2 className="w-5 h-5 animate-spin" />
              : <ArrowRight className="w-5 h-5" />}
              Continue
            </button>

            <div className="text-sm text-white/70 flex items-center justify-between">
              <Link className="text-tesoro-green hover:underline" to="/login">
                Back to sign in
              </Link>
              <button type="button" className="text-tesoro-green hover:underline"
                onClick={() => goto("code", { email: urlEmail, telegram: urlTelegram, channel: urlChannel }, searchParams, purpose, setSearchParams)}
              >
                I already have a code
              </button>
            </div>
          </form>
        ) : (
          <form onSubmit={(e) => onCodeSubmit(e, {purpose, channel, identifier, code, newPassword, confirmPassword}, verifyUrl, navigate, setStatus, setSubmitting)} className="space-y-5">
            <div>
              <label className="block text-xs font-medium text-white/70 mb-1" htmlFor="identifier2">
                Email or Telegram Chat ID
              </label>
              <input id="identifier2" required autoComplete="off" value={identifier}
                onChange={(e) => setIdentifier(e.target.value)} placeholder="name@example.com or 123456789"
                className="w-full rounded-xl bg-white/5 border border-white/15 px-3 py-2 text-sm outline-none focus:border-tesoro-green"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-white/70 mb-1" htmlFor="code">
                6-digit code
              </label>
              <input id="code" value={code} required autoComplete="off" 
                onChange={(e) => setCode(e.target.value)}
                inputMode="numeric" placeholder="123456" pattern="\d{6}" title="Enter the 6-digit code."
                className="w-full rounded-xl bg-white/5 border border-white/15 px-3 py-2 text-sm outline-none focus:border-tesoro-green"
              />
              <p className="text-xs text-white/50 mt-2">
                Codes are 6 digits and expire after a short period.
              </p>
            </div>

            {purpose === "reset" ? (
              <>
                <div>
                  <label className="block text-xs font-medium text-white/70 mb-1" htmlFor="newPassword">
                    New password
                  </label>
                  <input id="newPassword" value={newPassword} required autoComplete="off"
                    onChange={(e) => setNewPassword(e.target.value)} type="password"
                    className="w-full rounded-xl bg-white/5 border border-white/15 px-3 py-2 text-sm outline-none focus:border-tesoro-green"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-white/70 mb-1" htmlFor="confirmPassword">
                    Confirm new password
                  </label>
                  <input id="confirmPassword" value={confirmPassword} required autoComplete="off"
                    onChange={(e) => setConfirmPassword(e.target.value)} type="password"
                    className="w-full rounded-xl bg-white/5 border border-white/15 px-3 py-2 text-sm outline-none focus:border-tesoro-green"
                  />
                </div>
              </>
            ) : null}

            <div className="flex gap-3">
              <button type="button" disabled={submitting}
                onClick={() => onResendClick(setStatus, setSubmitting, { purpose, channel, identifier }, verifyUrl, loginUrl)}
                className="flex-1 rounded-2xl border border-white/15 bg-white/5 text-white font-semibold px-4 py-3 hover:bg-white/10 transition disabled:opacity-60 disabled:cursor-not-allowed"
              >
                Resend code
              </button>

              <button type="submit" disabled={submitting}
                className="flex-1 rounded-2xl bg-tesoro-green text-white cursor-pointer font-semibold px-4 py-3 hover:brightness-110 transition disabled:opacity-60 disabled:cursor-not-allowed flex items-center justify-center gap-2"
              >
                {submitting ? <Loader2 className="w-5 h-5 animate-spin" />
                : <KeyRound className="w-5 h-5" />}
                Verify
              </button>
            </div>

            <div className="text-sm text-white/70 flex items-center justify-between">
              <button type="button" className="text-tesoro-green hover:underline"
                onClick={() => goto("method", { email: urlEmail, telegram: urlTelegram, channel: urlChannel }, searchParams, purpose, setSearchParams)}
              >
                Choose method
              </button>
              <Link className="text-tesoro-green hover:underline" to="/login">
                Back to sign in
              </Link>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
