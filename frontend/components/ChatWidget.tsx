"use client";

import React, { useRef, useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { useChat, MODELS } from "@/context/ChatContext";
import MarkdownRenderer from "./MarkdownRenderer";
import { X, Minimize2, MessageSquare, Paperclip, Mic, Copy, Check } from "lucide-react";

export default function ChatWidget() {
  const {
    messages,
    input,
    setInput,
    isLoading,
    selectedModel,
    setSelectedModel,
    isWidgetOpen,
    setIsWidgetOpen,
    handleSend,
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
  }, [messages, isLoading, isWidgetOpen]);

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

  return (
    <div className="fixed bottom-4 right-4 sm:bottom-6 sm:right-6 z-[9999] flex flex-col items-end">
      <AnimatePresence>
        {!isWidgetOpen && (
          <motion.button
            initial={{ scale: 0, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0, opacity: 0 }}
            onClick={() => setIsWidgetOpen(true)}
            className="absolute bottom-0 right-0 w-14 h-14 bg-primary text-black rounded-full flex items-center justify-center shadow-lg hover:bg-primary/90 transition-colors group"
          >
            <div className="absolute inset-0 rounded-full bg-primary/40 animate-ping" />
            <MessageSquare size={24} className="relative z-10" />
          </motion.button>
        )}
      </AnimatePresence>

      <AnimatePresence>
        {isWidgetOpen && (
          <motion.div
            initial={{ y: 50, opacity: 0, scale: 0.95 }}
            animate={{ y: 0, opacity: 1, scale: 1 }}
            exit={{ y: 50, opacity: 0, scale: 0.95 }}
            className="absolute bottom-16 right-0 w-[calc(100vw-32px)] sm:w-[380px] h-[calc(100vh-140px)] sm:h-[520px] max-h-[80vh] glass-panel border border-white/10 rounded-2xl shadow-2xl flex flex-col overflow-hidden transform-gpu"
          >
            {/* Header */}
            <div className="h-14 border-b border-white/5 flex items-center justify-between px-4 bg-surface/50 backdrop-blur-md shrink-0">
              <div className="flex flex-col">
                <span className="font-bold text-white text-sm">ThreatMap AI</span>
                <span className="text-[10px] text-on-surface-variant">Powered by {MODELS.find(m => m.id === selectedModel)?.name}</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="relative" ref={dropdownRef}>
                  <button
                    onClick={() => setShowDropdown(!showDropdown)}
                    className="flex items-center gap-1 p-1.5 rounded border border-white/10 hover:bg-white/5 text-on-surface-variant"
                  >
                    <span className="material-symbols-outlined text-[14px]">smart_toy</span>
                  </button>
                  <AnimatePresence>
                    {showDropdown && (
                      <motion.div
                        initial={{ opacity: 0, y: 5 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: 5 }}
                        className="absolute right-0 mt-2 w-48 rounded-xl border border-white/10 bg-[#111827] shadow-xl overflow-hidden z-50"
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
                              className="w-full text-left px-3 py-2 text-xs hover:bg-white/5 transition-colors flex flex-col gap-0.5"
                            >
                              <span className={selectedModel === model.id ? "text-primary" : "text-white"}>{model.name}</span>
                              {model.badge && (
                                <span className={`text-[8px] uppercase font-bold px-1 rounded w-max ${
                                  model.badge === "Recommended" ? "bg-primary/20 text-primary" :
                                  model.badge === "Fastest" ? "bg-blue-500/20 text-blue-400" :
                                  "bg-red-500/20 text-red-400"
                                }`}>{model.badge}</span>
                              )}
                            </button>
                          ))}
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
                <button onClick={() => setIsWidgetOpen(false)} className="p-1 hover:bg-white/10 rounded text-on-surface-variant hover:text-white transition-colors">
                  <Minimize2 size={16} />
                </button>
                <button onClick={() => setIsWidgetOpen(false)} className="p-1 hover:bg-white/10 rounded text-on-surface-variant hover:text-white transition-colors">
                  <X size={16} />
                </button>
              </div>
            </div>

            {/* Chat Area */}
            <div className="flex-1 overflow-y-auto p-4 space-y-4 custom-scrollbar bg-background/30">
              {messages.map((msg, idx) => (
                <div key={idx} className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"} group`}>
                  <div className={`max-w-[85%] rounded-2xl px-4 py-3 ${
                    msg.role === "user" ? "bg-primary text-black font-medium" : "bg-surface-container-high text-white border border-white/5 shadow-lg relative backdrop-blur-md"
                  }`}>
                    {msg.role === "assistant" ? (
                      <div className="text-sm">
                        <MarkdownRenderer content={msg.content} />
                        <button
                          onClick={() => handleCopyMessage(msg.content, idx)}
                          className="absolute -bottom-2 -right-2 p-1.5 bg-surface-container-high border border-white/10 rounded text-on-surface-variant hover:text-white opacity-0 group-hover:opacity-100 transition-opacity"
                          title="Copy text"
                        >
                          {copiedMessageIdx === idx ? <Check size={12} className="text-primary"/> : <Copy size={12} />}
                        </button>
                      </div>
                    ) : (
                      <div className="whitespace-pre-wrap text-xs">{msg.content}</div>
                    )}
                  </div>
                </div>
              ))}
              {isLoading && (
                <div className="flex justify-start">
                  <div className="bg-surface-container-high border border-white/5 rounded-2xl px-4 py-3 flex gap-1.5 items-center backdrop-blur-md">
                    <div className="w-1.5 h-1.5 bg-primary rounded-full animate-bounce" style={{ animationDelay: "0ms" }} />
                    <div className="w-1.5 h-1.5 bg-primary rounded-full animate-bounce" style={{ animationDelay: "150ms" }} />
                    <div className="w-1.5 h-1.5 bg-primary rounded-full animate-bounce" style={{ animationDelay: "300ms" }} />
                  </div>
                </div>
              )}
              <div ref={messagesEndRef} />
            </div>

            {/* Input Area */}
            <div className="p-3 border-t border-white/5 bg-surface/50 backdrop-blur-md relative">
              {imageFile && (
                <div className="absolute bottom-full mb-2 left-4 bg-surface-container-high border border-white/10 p-1 rounded-lg flex items-center gap-2">
                  <img src={URL.createObjectURL(imageFile)} alt="Preview" className="w-10 h-10 object-cover rounded" />
                  <button onClick={() => setImageFile(null)} className="p-1 hover:bg-white/10 rounded"><X size={14} className="text-red-400"/></button>
                </div>
              )}
              {isListening && (
                <div className="absolute bottom-full mb-2 left-4 text-xs text-red-400 flex items-center gap-1 bg-surface-container-high px-2 py-1 rounded">
                  <span className="w-2 h-2 bg-red-400 rounded-full animate-pulse"/> Listening...
                </div>
              )}

              <div className="flex items-end gap-2 bg-surface-container-low border border-white/10 rounded-xl p-1.5">
                <input type="file" accept="image/*" className="hidden" ref={fileInputRef} onChange={handleFileChange} />
                <button onClick={() => fileInputRef.current?.click()} className="p-2 text-on-surface-variant hover:text-white rounded-lg">
                  <Paperclip size={18} className={imageFile ? "text-primary" : ""} />
                </button>
                <textarea
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder="Ask ThreatMap AI..."
                  className="flex-1 bg-transparent border-none text-white text-xs resize-none focus:ring-0 min-h-[36px] max-h-24 py-2 custom-scrollbar"
                  rows={1}
                />
                <button onClick={startVoiceInput} className="p-2 text-on-surface-variant hover:text-white rounded-lg">
                  <Mic size={18} className={isListening ? "text-red-400 animate-pulse" : ""} />
                </button>
                <button
                  onClick={onSubmit}
                  disabled={(!input.trim() && !imageFile) || isLoading}
                  className="h-9 w-9 bg-primary text-black rounded-lg flex items-center justify-center disabled:opacity-50 transition-colors"
                >
                  <span className="material-symbols-outlined text-[18px]">send</span>
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
