"use client";

import React, { createContext, useContext, useState, ReactNode } from "react";
import { api } from "@/lib/api";

export interface Message {
  role: "user" | "assistant";
  content: string;
}

interface ChatContextType {
  messages: Message[];
  input: string;
  setInput: (val: string) => void;
  isLoading: boolean;
  selectedModel: string;
  setSelectedModel: (val: string) => void;
  isWidgetOpen: boolean;
  setIsWidgetOpen: (val: boolean) => void;
  handleSend: (text: string, imageFile?: File | null) => Promise<void>;
  handleClear: () => void;
  toastMessage: string | null;
  showToast: (msg: string) => void;
}

const ChatContext = createContext<ChatContextType | undefined>(undefined);

export const MODELS = [
  { id: "openai/gpt-oss-120b", name: "GPT-OSS 120B", badge: "Recommended" },
  { id: "openai/gpt-oss-20b", name: "GPT-OSS 20B", badge: "Fastest" },
  { id: "qwen/qwen3.6-27b", name: "Qwen 3.6 27B", badge: "" },
  { id: "llama-3.3-70b-versatile", name: "Llama 3.3 70B", badge: "Legacy" }
];

export function ChatProvider({ children }: { children: ReactNode }) {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [selectedModel, setSelectedModel] = useState("openai/gpt-oss-120b");
  const [isWidgetOpen, setIsWidgetOpen] = useState(false);
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3000);
  };

  const handleSend = async (text: string, imageFile?: File | null) => {
    if (!text.trim() && !imageFile) return;

    const userMessage: Message = { 
      role: "user", 
      content: imageFile ? `[Attached Image] ${text}` : text.trim() 
    };
    
    const newMessages = [...messages, userMessage];
    setMessages(newMessages);
    setInput("");
    setIsLoading(true);

    try {
      let response;
      if (imageFile) {
        response = await api.askAiWithImage(text || "What is in this image?", imageFile);
      } else {
        const history = messages.map((m) => ({ role: m.role, content: m.content }));
        response = await api.askAi(text, history, selectedModel);
      }
      setMessages([...newMessages, { role: "assistant", content: response.response }]);
    } catch (error: any) {
      setMessages([
        ...newMessages,
        { role: "assistant", content: `**Error:** Could not reach AI service. ${error.message}` },
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleClear = () => {
    setMessages([]);
    setInput("");
  };

  return (
    <ChatContext.Provider
      value={{
        messages,
        input,
        setInput,
        isLoading,
        selectedModel,
        setSelectedModel,
        isWidgetOpen,
        setIsWidgetOpen,
        handleSend,
        handleClear,
        toastMessage,
        showToast,
      }}
    >
      {children}
    </ChatContext.Provider>
  );
}

export function useChat() {
  const context = useContext(ChatContext);
  if (context === undefined) {
    throw new Error("useChat must be used within a ChatProvider");
  }
  return context;
}
