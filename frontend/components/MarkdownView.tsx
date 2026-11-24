"use client";

import ReactMarkdown, { type Components } from "react-markdown";
import remarkGfm from "remark-gfm";

/** Markdown from a model, rendered with the app's tokens. Raw HTML is never rendered. */
const COMPONENTS: Components = {
  h1: ({ children }) => (
    <h3 className="mt-4 mb-2 text-base font-semibold text-[var(--ink)] first:mt-0">{children}</h3>
  ),
  h2: ({ children }) => (
    <h3 className="mt-5 mb-2 flex items-center gap-2 border-b border-slate-200 pb-1.5 text-[15px] font-semibold text-[var(--ink)] first:mt-0">
      {children}
    </h3>
  ),
  h3: ({ children }) => (
    <h4 className="mt-4 mb-1.5 text-sm font-semibold text-[var(--ink)] first:mt-0">{children}</h4>
  ),
  h4: ({ children }) => (
    <h5 className="mt-3 mb-1 text-sm font-medium text-[var(--ink)] first:mt-0">{children}</h5>
  ),
  p: ({ children }) => <p className="my-2 leading-relaxed first:mt-0 last:mb-0">{children}</p>,
  ul: ({ children }) => <ul className="my-2 list-disc space-y-1 pl-5 marker:text-slate-400">{children}</ul>,
  ol: ({ children }) => (
    <ol className="my-2 list-decimal space-y-1 pl-5 marker:font-medium marker:text-slate-500">{children}</ol>
  ),
  li: ({ children }) => <li className="pl-0.5 leading-relaxed">{children}</li>,
  strong: ({ children }) => <strong className="font-semibold text-[var(--ink)]">{children}</strong>,
  a: ({ children, href }) => (
    <a href={href} target="_blank" rel="noopener noreferrer" className="font-medium text-blue-700 underline-offset-2 hover:underline">
      {children}
    </a>
  ),
  blockquote: ({ children }) => (
    <blockquote className="my-3 border-l-2 border-blue-300 bg-blue-50/50 py-1 pl-3 text-[var(--muted)]">
      {children}
    </blockquote>
  ),
  hr: () => <hr className="my-4 border-slate-200" />,
  code: ({ children, className }) => (
    <code
      className={`rounded bg-slate-100 px-1 py-0.5 font-mono text-[12.5px] text-slate-800 ${className ?? ""}`}
    >
      {children}
    </code>
  ),
  pre: ({ children }) => (
    <pre className="my-3 overflow-x-auto rounded-md border border-slate-800 bg-slate-900 p-3 font-mono text-[12.5px] leading-relaxed text-slate-100 [&>code]:bg-transparent [&>code]:p-0 [&>code]:text-inherit">
      {children}
    </pre>
  ),
  table: ({ children }) => (
    <div className="my-3 overflow-x-auto rounded-md border border-slate-200">
      <table className="w-full border-collapse text-left text-xs">{children}</table>
    </div>
  ),
  thead: ({ children }) => <thead className="bg-slate-50 text-[var(--muted)]">{children}</thead>,
  th: ({ children }) => <th className="border-b border-slate-200 px-2.5 py-1.5 font-medium">{children}</th>,
  td: ({ children }) => <td className="border-b border-slate-100 px-2.5 py-1.5 align-top">{children}</td>,
};

export default function MarkdownView({ text }: { text: string }) {
  return (
    <div className="text-sm text-[var(--ink)]">
      <ReactMarkdown remarkPlugins={[remarkGfm]} components={COMPONENTS}>
        {text}
      </ReactMarkdown>
    </div>
  );
}
