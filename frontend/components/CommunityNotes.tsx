"use client";

import React, { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { motion, AnimatePresence } from "framer-motion";
import { MessageSquare, ThumbsUp, Send, RefreshCw, User } from "lucide-react";

interface Note {
  id: number;
  indicator: string;
  author: string;
  text: string;
  upvotes: number;
  created_at: string;
}

interface CommunityNotesProps {
  indicator: string;
}

export const CommunityNotes: React.FC<CommunityNotesProps> = ({ indicator }) => {
  const [notes, setNotes] = useState<Note[]>([]);
  const [loading, setLoading] = useState(true);
  const [text, setText] = useState("");
  const [author, setAuthor] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [upvotedIds, setUpvotedIds] = useState<Set<number>>(new Set());

  const fetchNotes = async () => {
    try {
      const data = await api.getNotes(indicator);
      setNotes(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchNotes(); }, [indicator]);

  const handleSubmit = async () => {
    if (!text.trim()) return;
    setSubmitting(true);
    try {
      await api.addNote(indicator, text.trim(), author.trim() || undefined);
      setText("");
      fetchNotes();
    } catch (e) {
      console.error(e);
    } finally {
      setSubmitting(false);
    }
  };

  const handleUpvote = async (noteId: number) => {
    if (upvotedIds.has(noteId)) return;
    try {
      await api.upvoteNote(noteId);
      setUpvotedIds(prev => new Set([...prev, noteId]));
      setNotes(prev => prev.map(n => n.id === noteId ? { ...n, upvotes: n.upvotes + 1 } : n));
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div className="glass-panel rounded-xl overflow-hidden">
      <div className="p-5 border-b border-white/5 flex items-center gap-3">
        <MessageSquare className="text-primary w-5 h-5" />
        <div>
          <h3 className="font-bold text-white text-sm">Community Notes</h3>
          <p className="text-[10px] text-on-surface-variant/70">
            Analyst observations shared by the community — verify independently
          </p>
        </div>
      </div>

      {/* Submit Form */}
      <div className="p-5 border-b border-white/5 space-y-3">
        <div className="flex gap-3">
          <div className="flex-1">
            <input
              value={author}
              onChange={e => setAuthor(e.target.value)}
              placeholder="Your name (optional)"
              className="w-full bg-surface-container-low border border-white/10 rounded-lg px-3 py-2 text-xs text-white placeholder-on-surface-variant/40 focus:outline-none focus:border-primary/50"
            />
          </div>
        </div>
        <div className="flex gap-2">
          <textarea
            value={text}
            onChange={e => setText(e.target.value)}
            placeholder="Add analyst note, observed behavior, or context about this IOC..."
            rows={2}
            className="flex-1 bg-surface-container-low border border-white/10 rounded-lg px-3 py-2 text-xs text-white placeholder-on-surface-variant/40 focus:outline-none focus:border-primary/50 resize-none"
          />
          <button
            onClick={handleSubmit}
            disabled={submitting || !text.trim()}
            className="px-4 py-2 bg-primary text-on-primary rounded-lg font-bold text-xs hover:opacity-90 disabled:opacity-50 transition-all flex items-center gap-1.5 self-end"
          >
            {submitting ? <RefreshCw size={12} className="animate-spin" /> : <Send size={12} />}
            POST
          </button>
        </div>
      </div>

      {/* Notes List */}
      <div className="divide-y divide-white/5 max-h-[400px] overflow-y-auto">
        {loading ? (
          <div className="flex items-center justify-center py-8">
            <RefreshCw className="w-5 h-5 text-primary animate-spin" />
          </div>
        ) : notes.length === 0 ? (
          <div className="py-8 text-center">
            <MessageSquare className="w-8 h-8 text-on-surface-variant/20 mx-auto mb-2" />
            <p className="text-xs text-on-surface-variant">No notes yet. Be the first analyst to comment.</p>
          </div>
        ) : (
          <AnimatePresence>
            {notes.map(note => (
              <motion.div
                key={note.id}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                className="px-5 py-4 flex gap-3"
              >
                <div className="p-1.5 rounded-full bg-surface-container-high border border-white/5 h-fit mt-0.5">
                  <User size={12} className="text-on-surface-variant" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between gap-2 mb-1">
                    <span className="text-xs font-bold text-white">{note.author}</span>
                    <span className="text-[10px] text-on-surface-variant/50">
                      {new Date(note.created_at).toLocaleDateString()}
                    </span>
                  </div>
                  <p className="text-xs text-on-surface-variant/90 leading-relaxed">{note.text}</p>
                  <button
                    onClick={() => handleUpvote(note.id)}
                    disabled={upvotedIds.has(note.id)}
                    className={`mt-2 flex items-center gap-1.5 text-[10px] font-mono-sm transition-all ${
                      upvotedIds.has(note.id) ? "text-primary" : "text-on-surface-variant hover:text-primary"
                    }`}
                  >
                    <ThumbsUp size={10} />
                    <span>{note.upvotes} helpful</span>
                  </button>
                </div>
              </motion.div>
            ))}
          </AnimatePresence>
        )}
      </div>
    </div>
  );
};

export default CommunityNotes;
