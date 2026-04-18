import { useState } from "react";
import { getRemediation } from "@/constants/remediationSteps";

type Tab = "console" | "cli" | "terraform";

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  return (
    <button
      onClick={handleCopy}
      className={`
        flex items-center gap-1.5 px-2.5 py-1 rounded-btn text-xs font-medium
        transition-all duration-150
        ${copied
          ? "bg-green-100 dark:bg-green-500/10 text-green-700 dark:text-green-400"
          : "bg-ghost-cream dark:bg-white/5 text-slate-gray hover:bg-ghost-cream/80 dark:hover:bg-white/10"
        }
      `}
    >
      {copied ? (
        <>
          <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
          </svg>
          Copied
        </>
      ) : (
        <>
          <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
              d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-4 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
          </svg>
          Copy
        </>
      )}
    </button>
  );
}

function CodeBlock({ code, language }: { code: string; language: string }) {
  return (
    <div className="rounded-xl border border-ghost-cream dark:border-white/5 overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2 bg-canvas-cream dark:bg-ink-black/50 border-b border-ghost-cream dark:border-white/5">
        <span className="text-[10px] font-semibold uppercase tracking-widest text-slate-gray/70">
          {language}
        </span>
        <CopyButton text={code} />
      </div>
      <pre className="overflow-x-auto p-4 text-xs leading-relaxed text-ink-black dark:text-canvas-cream bg-canvas-cream/50 dark:bg-ink-black/10 font-mono whitespace-pre">
        {code}
      </pre>
    </div>
  );
}

function ConsoleSteps({ steps }: { steps: string[] }) {
  return (
    <ol className="space-y-3">
      {steps.map((step, i) => (
        <li key={i} className="flex gap-3">
          <span className="
            flex-shrink-0 w-5 h-5 rounded-full mt-0.5
            bg-ghost-cream dark:bg-white/10
            text-ink-black dark:text-canvas-cream
            text-[10px] font-bold flex items-center justify-center
          ">
            {i + 1}
          </span>
          <p className="text-sm text-ink-black dark:text-canvas-cream leading-relaxed">
            {step}
          </p>
        </li>
      ))}
    </ol>
  );
}

interface Props {
  checkId: string;
  resource: string;
}

export default function RemediationTabs({ checkId, resource }: Props) {
  const [activeTab, setActiveTab] = useState<Tab>("console");
  const steps = getRemediation(checkId, resource);

  const tabs: { id: Tab; label: string }[] = [
    { id: "console", label: "AWS Console" },
    { id: "cli",     label: "AWS CLI"     },
    { id: "terraform", label: "Terraform" },
  ];

  return (
    <div className="bg-lifted-cream dark:bg-ink-black border border-ghost-cream dark:border-white/5 rounded-hero overflow-hidden shadow-elev-1">
      {/* Tab bar */}
      <div className="px-5 border-b border-ghost-cream dark:border-white/5">
        <div className="flex gap-0">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`
                px-4 py-3 text-xs font-semibold border-b-2 transition-all duration-150
                ${activeTab === tab.id
                  ? "border-ink-black text-ink-black dark:border-canvas-cream dark:text-canvas-cream"
                  : "border-transparent text-slate-gray hover:text-ink-black dark:hover:text-canvas-cream"
                }
              `}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Tab content */}
      <div className="px-5 py-5">
        {!steps ? (
          <p className="text-xs text-slate-gray italic">
            No remediation steps available for this check.
          </p>
        ) : (
          <>
            {activeTab === "console" && (
              <div>
                <div className="flex items-center gap-2 mb-4 p-2.5 rounded-lg bg-amber-50 dark:bg-amber-500/5 border border-amber-100 dark:border-amber-500/10">
                  <svg className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                  </svg>
                  <p className="text-xs text-amber-700 dark:text-amber-400">
                    Manual steps — open AWS Console to apply
                  </p>
                </div>
                <ConsoleSteps steps={steps.console} />
              </div>
            )}

            {activeTab === "cli" && (
              <div>
                <div className="flex items-center gap-2 mb-3 p-2.5 rounded-lg bg-blue-50 dark:bg-blue-500/5 border border-blue-100 dark:border-blue-500/10">
                  <svg className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
                  </svg>
                  <p className="text-xs text-blue-700 dark:text-blue-400">
                    Replace{" "}
                    <code className="font-mono bg-blue-100 dark:bg-blue-500/10 px-1 rounded text-[10px]">
                      {"<PLACEHOLDERS>"}
                    </code>
                    {" "}before running
                  </p>
                </div>
                <CodeBlock code={steps.cli} language="Shell / AWS CLI" />
              </div>
            )}

            {activeTab === "terraform" && (
              <div>
                <div className="flex items-center gap-2 mb-3 p-2.5 rounded-lg bg-purple-50 dark:bg-purple-500/5 border border-purple-100 dark:border-purple-500/10">
                  <svg className="w-3.5 h-3.5 text-purple-600 dark:text-purple-400 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M12.316 3.051a1 1 0 01.633 1.265l-4 12a1 1 0 11-1.898-.632l4-12a1 1 0 011.265-.633zM5.707 6.293a1 1 0 010 1.414L3.414 10l2.293 2.293a1 1 0 11-1.414 1.414l-3-3a1 1 0 010-1.414l3-3a1 1 0 011.414 0zm8.586 0a1 1 0 011.414 0l3 3a1 1 0 010 1.414l-3 3a1 1 0 11-1.414-1.414L16.586 10l-2.293-2.293a1 1 0 010-1.414z" clipRule="evenodd" />
                  </svg>
                  <p className="text-xs text-purple-700 dark:text-purple-400">
                    Add to your config and run{" "}
                    <code className="font-mono bg-purple-100 dark:bg-purple-500/10 px-1 rounded text-[10px]">
                      terraform apply
                    </code>
                  </p>
                </div>
                <CodeBlock code={steps.terraform} language="HCL / Terraform" />
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
