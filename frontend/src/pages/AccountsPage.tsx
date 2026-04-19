import { useState } from "react";
import { useAccount } from "@/hooks/useAccount";
import {
  preflight,
  createAccount,
  deleteAccount,
} from "@/api/accounts";
import type { PreflightResponse } from "@/types/account";
import EyebrowLabel from "@/components/shared/EyebrowLabel";

type Step = 1 | 2 | 3;
type ScriptTab = "bash" | "cf";

const STEPS = ["Generate", "Run Script", "Connect"];

const inputCls = [
  "w-full px-3 py-2 text-sm",
  "rounded-pill border border-ghost-cream dark:border-white/10",
  "bg-canvas-cream dark:bg-black",
  "text-ink-black dark:text-white",
  "placeholder:text-slate-gray dark:placeholder:text-gray-600",
  "outline-none focus:ring-2 focus:ring-ink-black/20",
].join(" ");

function StepIndicator({ current }: { current: Step }) {
  return (
    <div className="flex items-center gap-2 mb-5">
      {STEPS.map((label, i) => {
        const n = (i + 1) as Step;
        const active = n === current;
        const done = n < current;
        return (
          <div key={label} className="flex items-center gap-2">
            <div
              className={[
                "w-6 h-6 rounded-full flex items-center",
                "justify-center text-xs font-bold",
                active
                  ? "bg-ink-black text-canvas-cream"
                  : done
                    ? "bg-ghost-cream dark:bg-white/10 text-ink-black dark:text-gray-300"
                    : "bg-ghost-cream dark:bg-white/5 text-slate-gray dark:text-gray-600",
              ].join(" ")}
            >
              {done ? "✓" : n}
            </div>
            <span
              className={[
                "text-xs font-medium",
                active
                  ? "text-ink-black dark:text-white"
                  : "text-slate-gray dark:text-gray-600",
              ].join(" ")}
            >
              {label}
            </span>
            {i < STEPS.length - 1 && (
              <div className="w-6 h-px bg-ghost-cream dark:bg-white/10 mx-1" />
            )}
          </div>
        );
      })}
    </div>
  );
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <button
      onClick={copy}
      className={[
        "text-xs px-2 py-1 rounded-pill font-medium transition-colors",
        copied
          ? "bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400"
          : "bg-ghost-cream dark:bg-white/10 text-slate-gray dark:text-gray-400"
            + " hover:bg-[#E8E2DA] dark:hover:bg-white/20",
      ].join(" ")}
    >
      {copied ? "Copied!" : "Copy"}
    </button>
  );
}

const GUIDE_STEPS = [
  {
    n: 1,
    title: "Generate scripts",
    body: "Enter your target AWS account name and 12-digit account ID. CloudLine generates a unique external ID and IAM setup scripts scoped to that account.",
  },
  {
    n: 2,
    title: "Run the script",
    body: "Execute the Bash script in AWS CloudShell or your terminal, or deploy the CloudFormation template. This creates the CloudLineScanner IAM role with read-only permissions.",
  },
  {
    n: 3,
    title: "Connect",
    body: "Paste the Role ARN (auto-filled from step 1). CloudLine verifies the trust policy and external ID, then begins scanning.",
  },
];

const GUIDE_TIPS = [
  {
    icon: "🔒",
    text: "Read-only access only — CloudLine never modifies your resources.",
  },
  {
    icon: "🔑",
    text: "External IDs prevent confused-deputy attacks on the cross-account role.",
  },
  {
    icon: "🌍",
    text: "Repeat for each AWS account. All accounts appear in the global inventory.",
  },
];

function SetupGuide({ activeStep }: { activeStep: Step }) {
  return (
    <div className="bg-lifted-cream dark:bg-[#1c1c1b] border border-ghost-cream dark:border-white/5 rounded-hero p-5 shadow-elev-1 sticky top-4">
      <p className="text-[10px] font-semibold uppercase tracking-widest text-slate-gray dark:text-gray-600 mb-1">
        Setup Guide
      </p>
      <h3 className="text-sm font-bold text-ink-black dark:text-white mb-4">
        How to add a multi-account target
      </h3>

      <div className="space-y-4 mb-6">
        {GUIDE_STEPS.map((s) => {
          const isActive = s.n === activeStep;
          const isDone = s.n < activeStep;
          return (
            <div key={s.n} className="flex gap-3">
              <div
                className={[
                  "w-6 h-6 rounded-full shrink-0 flex items-center justify-center text-xs font-bold mt-0.5",
                  isActive
                    ? "bg-ink-black text-canvas-cream"
                    : isDone
                      ? "bg-ghost-cream dark:bg-white/10 text-slate-gray dark:text-gray-500"
                      : "bg-ghost-cream dark:bg-white/5 text-slate-gray dark:text-gray-600",
                ].join(" ")}
              >
                {isDone ? "✓" : s.n}
              </div>
              <div>
                <p
                  className={[
                    "text-xs font-semibold mb-0.5",
                    isActive
                      ? "text-ink-black dark:text-white"
                      : "text-slate-gray dark:text-gray-500",
                  ].join(" ")}
                >
                  {s.title}
                </p>
                <p className="text-xs text-slate-gray dark:text-gray-500 leading-relaxed">
                  {s.body}
                </p>
              </div>
            </div>
          );
        })}
      </div>

      <div className="border-t border-ghost-cream dark:border-white/5 pt-4 space-y-2.5">
        <p className="text-[10px] font-semibold uppercase tracking-widest text-slate-gray dark:text-gray-600 mb-2">
          Good to know
        </p>
        {GUIDE_TIPS.map((tip) => (
          <div key={tip.icon} className="flex gap-2.5 items-start">
            <span className="text-sm leading-none mt-0.5">{tip.icon}</span>
            <p className="text-xs text-slate-gray dark:text-gray-500 leading-relaxed">
              {tip.text}
            </p>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function AccountsPage() {
  const { accounts, isLoading, refresh } = useAccount();

  const [step, setStep] = useState<Step>(1);
  const [accountName, setAccountName] = useState("");
  const [accountId, setAccountId] = useState("");
  const [preflightData, setPreflightData] =
    useState<PreflightResponse | null>(null);
  const [scriptTab, setScriptTab] = useState<ScriptTab>("bash");
  const [confirmed, setConfirmed] = useState(false);
  const [roleArn, setRoleArn] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function resetWizard() {
    setStep(1);
    setAccountName("");
    setAccountId("");
    setPreflightData(null);
    setScriptTab("bash");
    setConfirmed(false);
    setRoleArn("");
    setError(null);
  }

  async function handleGenerate() {
    if (!accountName || !accountId) return;
    setSubmitting(true);
    setError(null);
    try {
      const data = await preflight({
        account_id: accountId,
        account_name: accountName,
      });
      setPreflightData(data);
      setRoleArn(
        `arn:aws:iam::${accountId}:role/CloudLineScanner`,
      );
      setStep(2);
    } catch {
      setError("Failed to generate setup scripts.");
    } finally {
      setSubmitting(false);
    }
  }

  async function handleConnect() {
    if (!roleArn || !preflightData) return;
    setSubmitting(true);
    setError(null);
    try {
      await createAccount({
        account_id: accountId,
        account_name: accountName,
        role_arn: roleArn,
        external_id: preflightData.external_id,
      });
      resetWizard();
      refresh();
    } catch {
      setError(
        "Failed to connect account. Verify the role ARN and trust policy.",
      );
    } finally {
      setSubmitting(false);
    }
  }

  function handleRemove(id: string) {
    deleteAccount(id).then(refresh);
  }

  const btnPrimary = [
    "px-4 py-2 text-sm font-medium rounded-btn",
    "bg-ink-black text-canvas-cream",
    "hover:opacity-90 disabled:opacity-40 disabled:cursor-not-allowed",
    "transition-opacity",
  ].join(" ");

  const btnSecondary = [
    "px-4 py-2 text-sm font-medium rounded-btn",
    "border border-ghost-cream dark:border-white/10",
    "text-slate-gray dark:text-gray-400",
    "hover:bg-ghost-cream dark:hover:bg-white/5 transition-colors",
  ].join(" ");

  return (
    <div className="space-y-4">
      <div>
        <EyebrowLabel className="mb-1">Accounts</EyebrowLabel>
        <h2 className="text-xl font-bold text-ink-black dark:text-white tracking-tight">
          AWS Accounts
        </h2>
      </div>

      {/* Two-pane layout */}
      <div className="grid grid-cols-1 lg:grid-cols-[1fr_320px] gap-4 items-start">

        {/* Left pane — wizard + account list */}
        <div className="space-y-4 min-w-0">

          {/* Wizard card */}
          <div className="bg-lifted-cream dark:bg-[#1c1c1b] border border-ghost-cream dark:border-white/5 rounded-hero p-5 shadow-elev-1">
            <StepIndicator current={step} />

            {/* Step 1 — Generate */}
            {step === 1 && (
              <div className="space-y-3">
                <p className="text-xs font-semibold uppercase tracking-widest text-slate-gray dark:text-gray-600">
                  Enter account details
                </p>
                <div className="flex flex-wrap gap-3">
                  <div className="flex-1 min-w-[140px]">
                    <input
                      type="text"
                      placeholder="Account Name"
                      value={accountName}
                      onChange={(e) => setAccountName(e.target.value)}
                      className={inputCls}
                    />
                  </div>
                  <div className="flex-1 min-w-[140px]">
                    <input
                      type="text"
                      placeholder="AWS Account ID"
                      value={accountId}
                      onChange={(e) => setAccountId(e.target.value)}
                      className={inputCls}
                    />
                  </div>
                </div>
                {error && (
                  <p className="text-xs text-red-500">{error}</p>
                )}
                <button
                  onClick={handleGenerate}
                  disabled={submitting || !accountName || !accountId}
                  className={btnPrimary}
                >
                  {submitting ? "Generating…" : "Generate Setup Scripts"}
                </button>
              </div>
            )}

            {/* Step 2 — Run Script */}
            {step === 2 && preflightData && (
              <div className="space-y-3">
                <p className="text-xs font-semibold uppercase tracking-widest text-slate-gray dark:text-gray-600">
                  Run the setup script in your AWS account
                </p>
                <p className="text-xs text-slate-gray dark:text-gray-400">
                  External ID:{" "}
                  <span className="font-mono text-ink-black dark:text-gray-300">
                    {preflightData.external_id}
                  </span>
                </p>

                <div className="inline-flex p-1 gap-1 bg-ghost-cream dark:bg-white/5 rounded-pill">
                  {(["bash", "cf"] as ScriptTab[]).map((tab) => (
                    <button
                      key={tab}
                      onClick={() => setScriptTab(tab)}
                      className={[
                        "px-3 py-1 text-xs font-medium rounded-pill transition-colors",
                        scriptTab === tab
                          ? "bg-ink-black text-canvas-cream"
                          : "text-slate-gray dark:text-gray-400 hover:text-ink-black dark:hover:text-gray-200",
                      ].join(" ")}
                    >
                      {tab === "bash" ? "Bash / CLI" : "CloudFormation"}
                    </button>
                  ))}
                </div>

                <div className="relative">
                  <div className="absolute top-2 right-2 z-10">
                    <CopyButton
                      text={
                        scriptTab === "bash"
                          ? preflightData.bash_script
                          : preflightData.cloudformation_template
                      }
                    />
                  </div>
                  <pre className="text-xs font-mono bg-ink-black text-canvas-cream rounded-hero p-4 overflow-x-auto max-h-64 whitespace-pre-wrap">
                    {scriptTab === "bash"
                      ? preflightData.bash_script
                      : preflightData.cloudformation_template}
                  </pre>
                </div>

                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={confirmed}
                    onChange={(e) => setConfirmed(e.target.checked)}
                    className="w-4 h-4 rounded border-ghost-cream"
                  />
                  <span className="text-sm text-ink-black dark:text-gray-300">
                    I've run the script successfully
                  </span>
                </label>

                <div className="flex gap-2">
                  <button onClick={() => setStep(1)} className={btnSecondary}>
                    Back
                  </button>
                  <button
                    onClick={() => setStep(3)}
                    disabled={!confirmed}
                    className={btnPrimary}
                  >
                    Continue
                  </button>
                </div>
              </div>
            )}

            {/* Step 3 — Connect */}
            {step === 3 && (
              <div className="space-y-3">
                <p className="text-xs font-semibold uppercase tracking-widest text-slate-gray dark:text-gray-600">
                  Enter the role ARN to connect
                </p>
                <input
                  type="text"
                  placeholder="arn:aws:iam::123456789012:role/CloudLineScanner"
                  value={roleArn}
                  onChange={(e) => setRoleArn(e.target.value)}
                  className={`${inputCls} font-mono`}
                />
                {error && (
                  <p className="text-xs text-red-500">{error}</p>
                )}
                <div className="flex gap-2">
                  <button onClick={() => setStep(2)} className={btnSecondary}>
                    Back
                  </button>
                  <button
                    onClick={handleConnect}
                    disabled={submitting || !roleArn}
                    className={btnPrimary}
                  >
                    {submitting ? "Connecting…" : "Connect Account"}
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Loading skeleton */}
          {isLoading && (
            <div className="bg-lifted-cream dark:bg-[#1c1c1b] border border-ghost-cream dark:border-white/5 rounded-hero p-8 shadow-elev-1 animate-pulse space-y-3">
              {Array.from({ length: 3 }).map((_, i) => (
                <div
                  key={i}
                  className="h-16 bg-ghost-cream dark:bg-white/5 rounded-hero"
                />
              ))}
            </div>
          )}

          {/* Empty state */}
          {!isLoading && accounts.length === 0 && (
            <div className="bg-lifted-cream dark:bg-[#1c1c1b] border border-ghost-cream dark:border-white/5 rounded-hero p-8 text-center shadow-elev-1">
              <p className="text-sm text-slate-gray dark:text-gray-400">
                No target accounts configured. Use the wizard above to add one.
              </p>
            </div>
          )}

          {/* Account list */}
          {accounts.length > 0 && (
            <div className="space-y-3">
              <p className="text-xs font-semibold uppercase tracking-widest text-slate-gray dark:text-gray-600 px-1">
                Connected Accounts
              </p>
              {accounts.map((a) => (
                <div
                  key={a.account_id}
                  className="bg-lifted-cream dark:bg-[#1c1c1b] border border-ghost-cream dark:border-white/5 rounded-hero p-5 shadow-elev-1"
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <p className="text-sm font-semibold text-ink-black dark:text-white">
                          {a.account_name}
                        </p>
                        <span className="text-xs font-mono px-1.5 py-0.5 rounded-pill bg-ghost-cream dark:bg-white/5 text-slate-gray dark:text-gray-500">
                          {a.account_id}
                        </span>
                        <span className="text-xs px-1.5 py-0.5 rounded-pill bg-green-50 dark:bg-green-500/10 text-green-700 dark:text-green-400 border border-green-200 dark:border-green-500/20 font-medium">
                          Connected
                        </span>
                      </div>
                      <p className="text-xs font-mono text-slate-gray dark:text-gray-600 truncate">
                        {a.role_arn}
                      </p>
                      <div className="flex items-center gap-4 mt-2">
                        <div className="flex items-center gap-1.5">
                          <span className="text-[10px] uppercase tracking-wider text-slate-gray dark:text-gray-600">
                            Regions:
                          </span>
                          {a.regions.map((r) => (
                            <span
                              key={r}
                              className="text-xs px-1.5 py-0.5 rounded-pill bg-ghost-cream dark:bg-white/5 text-ink-black dark:text-gray-400"
                            >
                              {r}
                            </span>
                          ))}
                        </div>
                        <div className="flex items-center gap-1.5">
                          <span className="text-[10px] uppercase tracking-wider text-slate-gray dark:text-gray-600">
                            Last scanned:
                          </span>
                          <span className="text-xs text-slate-gray dark:text-gray-400">
                            {a.last_scanned
                              ? new Date(a.last_scanned).toLocaleString()
                              : "Never"}
                          </span>
                        </div>
                      </div>
                    </div>
                    <button
                      onClick={() => handleRemove(a.account_id)}
                      className="px-3 py-1.5 text-xs font-medium rounded-btn border border-red-200 dark:border-red-500/20 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-500/10 transition-colors shrink-0"
                    >
                      Remove
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right pane — sticky setup guide */}
        <SetupGuide activeStep={step} />
      </div>
    </div>
  );
}
