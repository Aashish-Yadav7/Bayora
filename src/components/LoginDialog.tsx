import { useState, type FormEvent } from 'react';

interface Props {
  role: string;
  onClose: () => void;
  /** Returns null on success, 'OTP_REQUIRED' if a one-time code is needed, or an error message. */
  onSubmit: (username: string, password: string, otp: string) => Promise<string | null>;
}

export default function LoginDialog({ role, onClose, onSubmit }: Props) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [otp, setOtp] = useState('');
  const [needOtp, setNeedOtp] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError('');
    const result = await onSubmit(username.trim(), password, otp.trim());
    setBusy(false);
    if (result === 'OTP_REQUIRED') {
      setNeedOtp(true);
    } else if (result) {
      setError(result);
    }
  };

  const field = 'w-full rounded border border-slate-600 bg-slate-900 px-2 py-1 text-sm text-slate-100';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" role="dialog" aria-modal="true" aria-label="Sign in">
      <form onSubmit={submit} className="w-80 space-y-3 rounded-lg border border-slate-700 bg-slate-800 p-4">
        <h2 className="text-sm font-semibold text-slate-100">Sign in</h2>
        <p className="text-xs text-slate-400">
          Personal account: enter your username. Leave it blank to use the shared {role} credential as the password.
        </p>
        <input className={field} placeholder="Username (optional)" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} />
        <input className={field} type="password" placeholder="Password / role credential" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        {needOtp && (
          <input className={field} placeholder="6-digit authenticator code" inputMode="numeric" autoComplete="one-time-code" value={otp} onChange={(e) => setOtp(e.target.value)} required autoFocus />
        )}
        {error && <p className="text-xs text-red-400" role="alert">{error}</p>}
        <div className="flex justify-end gap-2">
          <button type="button" onClick={onClose} className="rounded border border-slate-600 px-3 py-1 text-xs text-slate-300">Cancel</button>
          <button type="submit" disabled={busy} className="rounded bg-sky-600 px-3 py-1 text-xs text-white disabled:opacity-50">{busy ? 'Signing in…' : 'Sign in'}</button>
        </div>
      </form>
    </div>
  );
}
