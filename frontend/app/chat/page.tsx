"use client";

import React, { useRef, useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { useChat, MODELS } from "@/context/ChatContext";
import MarkdownRenderer from "@/components/MarkdownRenderer";
import { Copy, Check, Paperclip, Mic, X, Download } from "lucide-react";

export default function ChatPage() {
  const {
    messages,
    input,
    setInput,
    isLoading,
    selectedModel,
    setSelectedModel,
    handleSend,
    handleClear,
    toastMessage,
    showToast
  } = useChat();

  const [showDropdown, setShowDropdown] = useState(false);
  const [copiedMessageIdx, setCopiedMessageIdx] = useState<number | null>(null);
  const [imageFile, setImageFile] = useState<File | null>(null);
  const [isListening, setIsListening] = useState(false);

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, isLoading]);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setShowDropdown(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const handleCopyMessage = (text: string, idx: number) => {
    navigator.clipboard.writeText(text);
    setCopiedMessageIdx(idx);
    setTimeout(() => setCopiedMessageIdx(null), 2000);
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    
    if (!file.type.startsWith("image/")) {
      showToast("Only images are supported for analysis");
      return;
    }
    if (file.size > 5 * 1024 * 1024) {
      showToast("Image must be smaller than 5MB");
      return;
    }
    setImageFile(file);
  };

  const startVoiceInput = () => {
    const SpeechRecognition = (window as any).SpeechRecognition || (window as any).webkitSpeechRecognition;
    if (!SpeechRecognition) {
      showToast("Voice input not supported in this browser");
      return;
    }

    const recognition = new SpeechRecognition();
    recognition.continuous = false;
    recognition.interimResults = true;
    recognition.lang = "en-US";

    recognition.onstart = () => setIsListening(true);
    recognition.onresult = (event: any) => {
      const transcript = Array.from(event.results)
        .map((result: any) => result[0].transcript)
        .join("");
      setInput(transcript);
    };
    recognition.onerror = () => setIsListening(false);
    recognition.onend = () => setIsListening(false);

    recognition.start();
  };

  const handleExportTxt = () => {
    if (messages.length === 0) return;
    const txtContent = messages.map(m => `[${m.role.toUpperCase()}] \n${m.content}\n`).join("\n----------------------------------------\n\n");
    const blob = new Blob([txtContent], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `ThreatMap_Chat_Export_${new Date().toISOString().split("T")[0]}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast("Chat exported successfully!");
  };

  const onSubmit = () => {
    if (!input.trim() && !imageFile) return;
    handleSend(input, imageFile);
    setImageFile(null);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      onSubmit();
    }
  };

  const SUGGESTIONS = [
    "What is a CVE?",
    "Explain MITRE ATT&CK",
    "How do I read a risk score?",
    "What does CRITICAL risk mean?"
  ];

  return (
    <div className="max-w-4xl mx-auto h-[calc(100vh-120px)] flex flex-col glass-panel rounded-xl overflow-hidden border border-white/5 relative">
      {/* Header */}
      <div className="h-16 border-b border-white/5 flex items-center justify-between px-6 shrink-0 bg-surface/50 backdrop-blur-sm z-10 relative">
        <div className="flex items-center gap-3">
          <span className="material-symbols-outlined text-primary text-[24px]">smart_toy</span>
          <div>
            <h1 className="font-bold text-white text-md font-headline-sm tracking-wide">ThreatMap AI</h1>
            <p className="text-[10px] text-on-surface-variant font-mono-sm">
              Powered by {MODELS.find(m => m.id === selectedModel)?.name}
            </p>
          </div>
        </div>
        
        <div className="flex items-center gap-3">
          {/* Model Switcher */}
          <div className="relative" ref={dropdownRef}>
            <button
              onClick={() => setShowDropdown(!showDropdown)}
              className="flex items-center gap-2 px-3 py-1.5 rounded border border-white/10 hover:bg-white/5 transition-colors bg-surface"
            >
              <span className="text-xs font-medium text-on-surface">
                {MODELS.find(m => m.id === selectedModel)?.name}
              </span>
              <span className="material-symbols-outlined text-[16px] text-on-surface-variant">
                expand_more
              </span>
            </button>

            <AnimatePresence>
              {showDropdown && (
                <motion.div
                  initial={{ opacity: 0, y: 5 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: 5 }}
                  className="absolute right-0 mt-2 w-64 rounded-xl border border-white/10 bg-[#111827] shadow-xl overflow-hidden z-50"
                >
                  <div className="py-1">
                    {MODELS.map((model) => (
                      <button
                        key={model.id}
                        onClick={() => {
                          setSelectedModel(model.id);
                          setShowDropdown(false);
                          showToast(`Switched to ${model.name}`);
                        }}
                        className={`w-full text-left px-4 py-3 text-sm flex items-center justify-between hover:bg-white/5 transition-colors ${
                          selectedModel === model.id ? "bg-white/5" : ""
                        }`}
                      >
                        <div className="flex flex-col gap-1">
                          <span className={`font-medium ${selectedModel === model.id ? "text-primary" : "text-white"}`}>
                            {model.name}
                          </span>
                          {model.badge && (
                            <span className={`text-[10px] uppercase font-bold tracking-wider w-max px-1.5 py-0.5 rounded ${
                              model.badge === "Recommended" ? "bg-primary/20 text-primary" :
                              model.badge === "Fastest" ? "bg-blue-500/20 text-blue-400" :
                              "bg-red-500/20 text-red-400"
                            }`}>
                              {model.badge}
                            </span>
                          )}
                        </div>
                        {selectedModel === model.id && (
                          <span className="material-symbols-outlined text-primary text-[18px]">
                            check
                          </span>
                        )}
                      </button>
                    ))}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {messages.length > 0 && (
            <>
              <button
                onClick={handleExportTxt}
                className="text-[11px] font-mono-sm text-on-surface-variant hover:text-white px-3 py-1.5 rounded border border-white/5 hover:bg-white/5 transition-colors flex items-center gap-1.5"
                title="Export as TXT"
              >
                <Download size={14} />
                EXPORT
              </button>
              <button
                onClick={handleClear}
                className="text-[11px] font-mono-sm text-error hover:text-error/80 px-3 py-1.5 rounded border border-error/20 hover:bg-error/10 transition-colors flex items-center gap-1.5"
                title="Clear Chat"
              >
                <span className="material-symbols-outlined text-[14px]">delete</span>
                CLEAR
              </button>
            </>
          )}
        </div>
      </div>

      {/* Toast Notification */}
      <AnimatePresence>
        {toastMessage && (
          <motion.div
            initial={{ opacity: 0, y: -20, x: "-50%" }}
            animate={{ opacity: 1, y: 0, x: "-50%" }}
            exit={{ opacity: 0, y: -20, x: "-50%" }}
            className="absolute top-20 left-1/2 -translate-x-1/2 z-50 bg-primary/20 border border-primary/30 text-primary px-4 py-2 rounded-full text-xs font-medium backdrop-blur-md shadow-lg"
          >
            {toastMessage}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Chat Area */}
      <div className="flex-1 overflow-y-auto p-6 space-y-6 hide-scrollbar">
        {messages.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-center space-y-8 animate-in fade-in duration-500">
            <div className="w-20 h-20 rounded-full bg-primary/10 border border-primary/20 flex items-center justify-center">
              <span className="material-symbols-outlined text-primary text-[40px]">psychiatry</span>
            </div>
            <div className="max-w-md space-y-2">
              <h2 className="text-xl font-bold text-white">Hi! I'm ThreatMap AI.</h2>
              <p className="text-sm text-on-surface-variant">
                Ask me anything about cybersecurity, threat intelligence, or how to use this platform.
              </p>
            </div>
            <div className="flex flex-wrap justify-center gap-3 max-w-lg">
              {SUGGESTIONS.map((suggestion) => (
                <button
                  key={suggestion}
                  onClick={() => handleSend(suggestion)}
                  className="px-4 py-2 bg-surface-container-low hover:bg-white/5 border border-white/5 rounded-full text-xs text-on-surface transition-colors"
                >
                  {suggestion}
                </button>
              ))}
            </div>
          </div>
        ) : (
          <div className="space-y-6 pb-4">
            <AnimatePresence initial={false}>
              {messages.map((msg, idx) => (
                <motion.div
                  key={idx}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"} group`}
                >
                  <div
                    className={`max-w-[80%] rounded-2xl px-5 py-4 ${
                      msg.role === "user"
                        ? "bg-[#00D4AA] text-black font-medium"
                        : "bg-[#111827] text-white border border-white/5 shadow-lg relative"
                    }`}
                  >
                    {msg.role === "assistant" ? (
                      <div>
                        <MarkdownRenderer content={msg.content} />
                        <button
                          onClick={() => handleCopyMessage(msg.content, idx)}
                          className="absolute -bottom-3 -right-3 p-2 bg-surface-container-high border border-white/10 rounded-lg text-on-surface-variant hover:text-white opacity-0 group-hover:opacity-100 transition-opacity shadow-lg"
                          title="Copy text"
                        >
                          {copiedMessageIdx === idx ? <Check size={14} className="text-primary"/> : <Copy size={14} />}
                        </button>
                      </div>
                    ) : (
                      <div className="whitespace-pre-wrap text-sm">{msg.content}</div>
                    )}
                  </div>
                </motion.div>
              ))}
            </AnimatePresence>

            {isLoading && (
              <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex justify-start">
                <div className="bg-[#111827] border border-white/5 rounded-2xl px-5 py-4 shadow-lg flex items-center gap-2">
                  <div className="w-2 h-2 bg-primary rounded-full animate-bounce" style={{ animationDelay: "0ms" }} />
                  <div className="w-2 h-2 bg-primary rounded-full animate-bounce" style={{ animationDelay: "150ms" }} />
                  <div className="w-2 h-2 bg-primary rounded-full animate-bounce" style={{ animationDelay: "300ms" }} />
                </div>
              </motion.div>
            )}
            <div ref={messagesEndRef} />
          </div>
        )}
      </div>

      {/* Input Area */}
      <div className="p-4 bg-surface/80 backdrop-blur-md border-t border-white/5 relative">
        {imageFile && (
          <div className="absolute bottom-full mb-3 left-6 bg-surface-container-high border border-white/10 p-1.5 rounded-lg flex items-center gap-3 shadow-xl">
            <img src={URL.createObjectURL(imageFile)} alt="Preview" className="w-16 h-16 object-cover rounded" />
            <button onClick={() => setImageFile(null)} className="p-1 hover:bg-white/10 rounded-lg"><X size={16} className="text-red-400"/></button>
          </div>
        )}
        
        {isListening && (
          <div className="absolute bottom-full mb-3 left-6 text-sm text-red-400 flex items-center gap-2 bg-surface-container-high px-3 py-1.5 rounded-lg shadow-xl">
            <span className="w-2.5 h-2.5 bg-red-400 rounded-full animate-pulse"/> Listening...
          </div>
        )}

        <div className="max-w-4xl mx-auto flex items-end gap-2 bg-surface-container-low border border-white/10 rounded-xl p-2 focus-within:border-primary/50 focus-within:ring-1 focus-within:ring-primary/50 transition-all">
          <input type="file" accept="image/*" className="hidden" ref={fileInputRef} onChange={handleFileChange} />
          <button onClick={() => fileInputRef.current?.click()} className="p-2.5 text-on-surface-variant hover:text-white rounded-lg transition-colors">
            <Paperclip size={20} className={imageFile ? "text-primary" : ""} />
          </button>
          
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Ask ThreatMap AI..."
            className="flex-1 bg-transparent border-none text-white text-sm resize-none focus:ring-0 min-h-[44px] max-h-32 py-3 px-2 custom-scrollbar"
            rows={1}
            disabled={isLoading}
          />
          
          <button onClick={startVoiceInput} className="p-2.5 text-on-surface-variant hover:text-white rounded-lg transition-colors">
            <Mic size={20} className={isListening ? "text-red-400 animate-pulse" : ""} />
          </button>

          <button
            onClick={onSubmit}
            disabled={(!input.trim() && !imageFile) || isLoading}
            className="h-11 w-11 shrink-0 bg-primary text-on-primary rounded-lg flex items-center justify-center hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            <span className="material-symbols-outlined text-[20px]">send</span>
          </button>
        </div>
        <div className="text-center mt-2">
          <span className="text-[10px] text-on-surface-variant font-mono-sm">
            AI can make mistakes. Verify critical security intelligence.
          </span>
        </div>
      </div>
    </div>
  );
}
