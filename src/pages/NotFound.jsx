import { Link } from "react-router-dom";
import { AlertTriangle, ArrowRight } from "lucide-react";

export default function NotFound() {
  return (
    <div className="min-h-screen bg-tesoro-black text-white flex items-center justify-center px-4 py-10">
      <div className="w-full max-w-md rounded-[2rem] border border-white/10 bg-white/5 backdrop-blur-xl shadow-2xl p-8">
        <div className="flex items-start gap-3 mb-4">
          <div className="p-3 rounded-2xl bg-white/10 border border-white/10">
            <AlertTriangle className="w-6 h-6 text-tesoro-yellow" />
          </div>
          <div>
            <h1 className="text-2xl font-bold font-display">Page not found</h1>
            <p className="text-sm text-white/70">
              The route you requested does not exist in this service.
            </p>
          </div>
        </div>

        <Link
          to="/login"
          className="w-full rounded-2xl bg-tesoro-green text-black font-semibold px-4 py-3 hover:brightness-110 transition flex items-center justify-center gap-2"
        >
          <ArrowRight className="w-5 h-5" />
          Go to sign in
        </Link>
      </div>
    </div>
  );
}
