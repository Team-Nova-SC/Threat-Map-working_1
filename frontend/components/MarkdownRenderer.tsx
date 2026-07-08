"use client";

import React, { useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";
import { vscDarkPlus } from "react-syntax-highlighter/dist/esm/styles/prism";
import { Copy, Check } from "lucide-react";

interface MarkdownRendererProps {
  content: string;
}

export default function MarkdownRenderer({ content }: MarkdownRendererProps) {
  const [copiedCodeId, setCopiedCodeId] = useState<string | null>(null);

  const handleCopyCode = (code: string, id: string) => {
    navigator.clipboard.writeText(code);
    setCopiedCodeId(id);
    setTimeout(() => setCopiedCodeId(null), 2000);
  };

  return (
    <div className="prose prose-invert max-w-none prose-sm prose-p:leading-relaxed prose-pre:p-0 prose-pre:bg-transparent">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          code({ node, inline, className, children, ...props }: any) {
            const match = /language-(\w+)/.exec(className || "");
            const isCodeBlock = !inline && match;
            const codeString = String(children).replace(/\n$/, "");
            const codeId = Math.random().toString(36).substr(2, 9);

            if (isCodeBlock) {
              return (
                <div className="relative group rounded-md overflow-hidden border border-white/10 my-4 bg-[#1E1E1E]">
                  <div className="flex items-center justify-between px-4 py-2 bg-black/40 border-b border-white/5">
                    <span className="text-xs text-on-surface-variant font-mono uppercase">{match[1]}</span>
                    <button
                      onClick={() => handleCopyCode(codeString, codeId)}
                      className="text-on-surface-variant hover:text-white transition-colors flex items-center gap-1.5"
                      title="Copy code"
                    >
                      {copiedCodeId === codeId ? (
                        <Check size={14} className="text-primary" />
                      ) : (
                        <Copy size={14} />
                      )}
                      <span className="text-[10px] uppercase font-bold tracking-wider">
                        {copiedCodeId === codeId ? "Copied" : "Copy"}
                      </span>
                    </button>
                  </div>
                  <SyntaxHighlighter
                    {...props}
                    style={vscDarkPlus}
                    language={match[1]}
                    PreTag="div"
                    customStyle={{
                      margin: 0,
                      padding: "1rem",
                      background: "transparent",
                      fontSize: "13px",
                    }}
                  >
                    {codeString}
                  </SyntaxHighlighter>
                </div>
              );
            }
            return (
              <code {...props} className="bg-white/10 text-primary px-1.5 py-0.5 rounded text-xs font-mono">
                {children}
              </code>
            );
          },
          table({ children }) {
            return (
              <div className="overflow-x-auto my-6 border border-white/10 rounded-lg">
                <table className="w-full text-left border-collapse text-sm">
                  {children}
                </table>
              </div>
            );
          },
          thead({ children }) {
            return <thead className="bg-white/5 border-b border-white/10 text-white font-medium">{children}</thead>;
          },
          tbody({ children }) {
            return <tbody className="divide-y divide-white/5 text-on-surface-variant">{children}</tbody>;
          },
          th({ children }) {
            return <th className="px-4 py-3 font-semibold">{children}</th>;
          },
          td({ children }) {
            return <td className="px-4 py-3">{children}</td>;
          },
          strong({ children }) {
            return <strong className="text-white font-semibold">{children}</strong>;
          },
          ul({ children }) {
            return <ul className="list-disc pl-5 my-4 space-y-1 marker:text-primary/70">{children}</ul>;
          },
          ol({ children }) {
            return <ol className="list-decimal pl-5 my-4 space-y-1 marker:text-primary/70">{children}</ol>;
          },
        }}
      >
        {content}
      </ReactMarkdown>
    </div>
  );
}
