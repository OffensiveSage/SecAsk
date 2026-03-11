"use client";

import { ArchitectureDiagram } from "@/components/ArchitectureDiagram";
import { ModelSettings } from "@/components/ModelSettings";
import {
  detectWebGPUAvailability,
  formatWebGPUReason,
  type WebGPUAvailabilityReason,
} from "@/lib/webgpu";
import { useEffect, useState, useRef, useCallback } from "react";
import { useRouter } from "next/navigation";

const CHAT_STORAGE_PREFIX = "gitask-chat-";
const EXAMPLE_REPOSITORIES = [
  { owner: "mlc-ai", repo: "web-llm" },
  { owner: "huggingface", repo: "smolagents" },
  { owner: "FloareDor", repo: "gitask" },
];

// SecAsk Papercut Layers design tokens (inline style helpers)
const SHADOW_1 = "3px 3px 0px #1A1A1A";
const SHADOW_2 = "5px 5px 0px #1A1A1A";
const INK = "#1A1A1A";
const SLATE = "#5B7FA5";

interface SavedChatEntry {
  id: string;
  storageKey: string;
  owner: string;
  repo: string;
  chatId: string | null;
  messageCount: number;
  lastUpdated: number;
  label: string;
}

function buildChatLabel(messages: Array<{ role?: string; content?: string }>, fallback: string): string {
  const firstUserMessage = messages.find(
    (m) => m?.role === "user" && typeof m.content === "string" && m.content.trim().length > 0
  );
  if (!firstUserMessage || !firstUserMessage.content) return fallback;
  const compact = firstUserMessage.content.trim().replace(/\s+/g, " ");
  return compact.length > 36 ? `${compact.slice(0, 36)}...` : compact;
}

function parseSavedChatEntries(key: string, raw: string): SavedChatEntry[] {
  if (!key.startsWith(CHAT_STORAGE_PREFIX)) return [];
  const repoPath = key.slice(CHAT_STORAGE_PREFIX.length);
  const slashIndex = repoPath.indexOf("/");
  if (slashIndex <= 0 || slashIndex >= repoPath.length - 1) return [];

  const owner = repoPath.slice(0, slashIndex);
  const repo = repoPath.slice(slashIndex + 1);

  try {
    const parsed = JSON.parse(raw) as
      | Array<{ role?: string; content?: string }>
      | {
          activeChatId?: string;
          sessions?: Array<{
            chat_id?: string;
            title?: string;
            updatedAt?: number;
            messages?: Array<{ role?: string; content?: string }>;
          }>;
        };

    // Legacy format: Message[]
    if (Array.isArray(parsed)) {
      const messages = parsed;
      if (messages.length === 0) return [];
      return [
        {
          id: `${key}::legacy`,
          storageKey: key,
          owner,
          repo,
          chatId: null,
          messageCount: messages.length,
          lastUpdated: 0,
          label: buildChatLabel(messages, "Chat 1"),
        },
      ];
    }

    if (!parsed || !Array.isArray(parsed.sessions) || parsed.sessions.length === 0) return [];
    return parsed.sessions
      .filter((session) => session && typeof session.chat_id === "string")
      .map((session, index) => {
        const messages = Array.isArray(session.messages) ? session.messages : [];
        const fallbackTitle = `Chat ${index + 1}`;
        const label = typeof session.title === "string" && session.title.trim().length > 0
          ? session.title
          : buildChatLabel(messages, fallbackTitle);
        return {
          id: `${key}::${session.chat_id}`,
          storageKey: key,
          owner,
          repo,
          chatId: session.chat_id ?? null,
          messageCount: messages.length,
          lastUpdated: typeof session.updatedAt === "number" ? session.updatedAt : 0,
          label,
        };
      });
  } catch {
    return [];
  }
}

export default function LandingPage() {
  const [url, setUrl] = useState("");
  const [error, setError] = useState("");
  const [savedChats, setSavedChats] = useState<SavedChatEntry[]>([]);
  const [starCount, setStarCount] = useState<number | null>(null);
  const [isHowVisible, setIsHowVisible] = useState(false);
  const [gpuSupported, setGpuSupported] = useState(true);
  const [gpuSupportReason, setGpuSupportReason] =
    useState<WebGPUAvailabilityReason>("ok");
  const [isMobile, setIsMobile] = useState(false);
  const howSectionRef = useRef<HTMLElement>(null);
  const router = useRouter();

  const loadSavedChats = useCallback(() => {
    if (typeof window === "undefined") return;
    try {
      const entries: SavedChatEntry[] = [];
      for (const key of Object.keys(localStorage)) {
        if (!key.startsWith(CHAT_STORAGE_PREFIX)) continue;
        const raw = localStorage.getItem(key);
        if (!raw) continue;
        entries.push(...parseSavedChatEntries(key, raw));
      }

      entries.sort((a, b) => {
        if (a.lastUpdated !== b.lastUpdated) return b.lastUpdated - a.lastUpdated;
        return `${a.owner}/${a.repo}`.localeCompare(`${b.owner}/${b.repo}`);
      });
      setSavedChats(entries);
    } catch (e) {
      console.warn("Failed to scan local chat storage:", e);
      setSavedChats([]);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const availability = await Promise.race([
        detectWebGPUAvailability(),
        new Promise<{ supported: true; reason: "ok" }>((resolve) =>
          setTimeout(() => resolve({ supported: true, reason: "ok" }), 1500)
        ),
      ]);
      if (cancelled) return;

      setGpuSupported(availability.supported);
      setGpuSupportReason(availability.reason);
      if (!availability.supported) {
        console.info("WebGPU unavailable:", availability.reason, availability.error ?? "");
      }
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    const check = () => setIsMobile(window.innerWidth < 600);
    check();
    window.addEventListener("resize", check);
    return () => window.removeEventListener("resize", check);
  }, []);

  useEffect(() => {
    fetch("https://api.github.com/repos/FloareDor/gitask")
      .then((r) => r.json())
      .then((d) => { if (typeof d.stargazers_count === "number") setStarCount(d.stargazers_count); })
      .catch(() => {});
  }, []);

  useEffect(() => {
    const node = howSectionRef.current;
    if (!node) {
      return;
    }

    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setIsHowVisible(true);
          observer.disconnect();
        }
      },
      { threshold: 0.22 }
    );

    observer.observe(node);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    loadSavedChats();
    const handleVisibility = () => {
      if (document.visibilityState === "visible") loadSavedChats();
    };
    window.addEventListener("focus", loadSavedChats);
    window.addEventListener("storage", loadSavedChats);
    document.addEventListener("visibilitychange", handleVisibility);
    return () => {
      window.removeEventListener("focus", loadSavedChats);
      window.removeEventListener("storage", loadSavedChats);
      document.removeEventListener("visibilitychange", handleVisibility);
    };
  }, [loadSavedChats]);

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");

    const match = url.match(
      /(?:https?:\/\/)?(?:www\.)?github\.com\/([^\/]+)\/([^\/\s]+)/
    );

    if (!match) {
      setError("Please enter a valid GitHub URL (e.g. https://github.com/owner/repo)");
      return;
    }

    const owner = match[1];
    const repo = match[2].replace(/\.git$/, "");
    router.push(`/${owner}/${repo}`);
  }

  function handleOpenSavedChat(chat: SavedChatEntry) {
    if (typeof window !== "undefined" && chat.chatId) {
      try {
        const raw = localStorage.getItem(chat.storageKey);
        if (raw) {
          const parsed = JSON.parse(raw) as { activeChatId?: string; sessions?: unknown[] };
          if (parsed && Array.isArray(parsed.sessions)) {
            localStorage.setItem(
              chat.storageKey,
              JSON.stringify({
                ...parsed,
                activeChatId: chat.chatId,
              })
            );
          }
        }
      } catch {
        // Ignore storage parse/write failures and continue routing.
      }
    }
    router.push(`/${chat.owner}/${chat.repo}`);
  }

  function handleDeleteSavedChat(chat: SavedChatEntry) {
    if (typeof window !== "undefined") {
      const confirmed = window.confirm("Delete local chats for this repository?");
      if (!confirmed) return;
      if (!chat.chatId) {
        localStorage.removeItem(chat.storageKey);
        loadSavedChats();
        return;
      }
      try {
        const raw = localStorage.getItem(chat.storageKey);
        if (!raw) {
          loadSavedChats();
          return;
        }
        const parsed = JSON.parse(raw) as {
          activeChatId?: string;
          sessions?: Array<{
            chat_id?: string;
            title?: string;
            updatedAt?: number;
            messages?: Array<{ role?: string; content?: string }>;
          }>;
        };
        if (!parsed || !Array.isArray(parsed.sessions)) {
          localStorage.removeItem(chat.storageKey);
          loadSavedChats();
          return;
        }
        const nextSessions = parsed.sessions.filter((session) => session.chat_id !== chat.chatId);
        if (nextSessions.length === 0) {
          localStorage.removeItem(chat.storageKey);
        } else {
          const nextActive = nextSessions.some((session) => session.chat_id === parsed.activeChatId)
            ? parsed.activeChatId
            : nextSessions[0].chat_id;
          localStorage.setItem(
            chat.storageKey,
            JSON.stringify({
              activeChatId: nextActive,
              sessions: nextSessions,
            })
          );
        }
      } catch {
        localStorage.removeItem(chat.storageKey);
      }
      loadSavedChats();
    }
  }

  function handleDeleteAllSavedChats() {
    if (savedChats.length === 0) return;
    if (typeof window !== "undefined") {
      const confirmed = window.confirm("Delete all local chats across repositories?");
      if (!confirmed) return;
      const keys = new Set(savedChats.map((entry) => entry.storageKey));
      for (const key of keys) {
        localStorage.removeItem(key);
      }
      setSavedChats([]);
    }
  }

  function handleOpenLLMSettings() {
    if (typeof window === "undefined") return;
    window.dispatchEvent(new Event("gitask-open-llm-settings"));
  }

  // isMobile is kept in state for potential future use; CSS grid handles responsive layout
  void isMobile;

  return (
    <div style={{ minHeight: "100vh", background: "var(--page-bg)", color: "var(--page-text)", fontFamily: "var(--font-sans)" }}>
      {/* NAV */}
      <nav style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "16px 40px",
        borderBottom: "2.5px solid var(--page-border)",
        background: "var(--bg-paper)",
        position: "sticky",
        top: 0,
        zIndex: 40,
        boxShadow: SHADOW_1,
      }}>
        <span style={{ fontFamily: "var(--font-display)", fontWeight: 900, fontSize: "1.25rem", letterSpacing: "0.02em", color: "var(--page-text)", textTransform: "uppercase" }}>
          SecAsk
        </span>
        <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
          <ModelSettings />
          <a
            href="https://github.com/FloareDor/gitask"
            target="_blank"
            rel="noopener noreferrer"
            style={{
              fontSize: "12px",
              fontWeight: 700,
              color: "var(--page-text)",
              textDecoration: "none",
              border: "2.5px solid var(--page-border)",
              padding: "6px 14px",
              fontFamily: "var(--font-sans)",
              textTransform: "uppercase",
              letterSpacing: "0.05em",
              boxShadow: "var(--shadow-subtle)",
            }}
          >
            GitHub ↗
          </a>
        </div>
      </nav>

      {/* HERO */}
      <section style={{
        minHeight: "80vh",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        padding: "80px 24px",
        textAlign: "center",
        background: "var(--page-bg)",
      }}>
        {/* Status badge */}
        <div style={{
          display: "inline-flex",
          alignItems: "center",
          gap: 8,
          padding: "6px 16px",
          border: "2px solid var(--page-border)",
          fontFamily: "var(--font-mono)",
          fontSize: "11px",
          fontWeight: 600,
          letterSpacing: "0.08em",
          textTransform: "uppercase",
          color: "var(--page-text-muted)",
          marginBottom: 32,
          background: "var(--bg-paper)",
          boxShadow: "var(--shadow-subtle)",
        }}>
          <span style={{ width: 7, height: 7, borderRadius: "50%", background: "#6B8F71", display: "inline-block" }} className="pulse" />
          Browser-native · No server · Keys stay local
        </div>

        <h1 style={{
          fontFamily: "var(--font-display)",
          fontSize: "clamp(2.5rem, 7vw, 5.5rem)",
          fontWeight: 900,
          lineHeight: 1.05,
          letterSpacing: "0.01em",
          color: "var(--page-text)",
          marginBottom: 24,
          maxWidth: 900,
          textTransform: "uppercase",
        }}>
          Ask your<br />security stack<br />anything.
        </h1>

        <p style={{
          fontSize: "clamp(1rem, 2vw, 1.15rem)",
          color: "var(--page-text-dim)",
          lineHeight: 1.65,
          maxWidth: 560,
          marginBottom: 40,
          fontFamily: "var(--font-sans)",
        }}>
          Index ATT&CK, Sigma rules, NVD, NIST, and your GitHub repos.
          Chat across all sources simultaneously. Embeddings, retrieval,
          and storage — all on-device.
        </p>

        {/* WebGPU warning — only when !gpuSupported */}
        {!gpuSupported && (
          <div style={{
            width: "100%",
            maxWidth: 620,
            textAlign: "left",
            border: "2.5px solid #E8943A",
            background: "#FFF3E0",
            padding: "14px 18px",
            marginBottom: 24,
            display: "flex",
            flexDirection: "column",
            gap: 8,
            boxShadow: SHADOW_1,
          }}>
            <strong style={{ fontSize: "13px", color: "#E8943A", fontFamily: "var(--font-display)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
              Local WebGPU inference unavailable in this browser.
            </strong>
            <p style={{ margin: 0, fontSize: "12px", color: "#9B5E1A", lineHeight: 1.5, fontFamily: "var(--font-sans)" }}>
              Use Gemini or Groq instead — open settings and enter your API key.
              Local indexing still works on CPU, just slower.
              {gpuSupportReason !== "ok"
                ? ` ${formatWebGPUReason(gpuSupportReason)}`
                : ""}
            </p>
            <button
              type="button"
              onClick={handleOpenLLMSettings}
              style={{
                alignSelf: "flex-start",
                fontSize: "12px",
                padding: "6px 12px",
                border: "2px solid #E8943A",
                background: "#E8943A",
                cursor: "pointer",
                fontWeight: 700,
                color: "#FFFDF7",
                fontFamily: "var(--font-sans)",
                textTransform: "uppercase",
                letterSpacing: "0.05em",
              }}
            >
              Open Settings
            </button>
          </div>
        )}

        {/* URL form */}
        <div style={{ width: "100%", maxWidth: 620, display: "flex", flexDirection: "column", gap: 10 }}>
          <form
            onSubmit={handleSubmit}
            style={{
              display: "flex",
              width: "100%",
              border: "2.5px solid var(--page-border)",
              boxShadow: SHADOW_1,
            }}
          >
            <input
              type="text"
              placeholder="github.com/owner/repo"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              id="repo-url-input"
              style={{
                flex: 1,
                padding: "16px 20px",
                fontFamily: "var(--font-mono)",
                fontSize: "1rem",
                border: "none",
                outline: "none",
                background: "var(--bg-paper)",
                color: "var(--page-text)",
              }}
            />
            <button
              type="submit"
              id="go-btn"
              style={{
                padding: "16px 28px",
                background: INK,
                color: "#FFFDF7",
                border: "none",
                borderLeft: `2.5px solid ${INK}`,
                cursor: "pointer",
                fontWeight: 700,
                fontSize: "0.875rem",
                fontFamily: "var(--font-display)",
                whiteSpace: "nowrap",
                textTransform: "uppercase",
                letterSpacing: "0.05em",
                transition: "transform 0.1s ease, box-shadow 0.1s ease",
              }}
              onMouseEnter={(e) => {
                const el = e.currentTarget as HTMLButtonElement;
                el.style.transform = "translate(-1px,-1px)";
                el.style.boxShadow = SHADOW_2;
              }}
              onMouseLeave={(e) => {
                const el = e.currentTarget as HTMLButtonElement;
                el.style.transform = "";
                el.style.boxShadow = "";
              }}
              onMouseDown={(e) => {
                const el = e.currentTarget as HTMLButtonElement;
                el.style.transform = "translate(2px,2px)";
                el.style.boxShadow = "none";
              }}
              onMouseUp={(e) => {
                const el = e.currentTarget as HTMLButtonElement;
                el.style.transform = "";
                el.style.boxShadow = "";
              }}
            >
              Explore Repo →
            </button>
          </form>
          {error && (
            <p style={{
              color: "#D94F3B",
              fontSize: "13px",
              textAlign: "left",
              fontFamily: "var(--font-mono)",
              padding: "8px 12px",
              background: "#FDF0EE",
              border: "2px solid #D94F3B",
            }}>
              {error}
            </p>
          )}
        </div>

        {/* GitHub star link */}
        <div style={{ marginTop: 24 }}>
          <a
            href="https://github.com/FloareDor/gitask"
            target="_blank"
            rel="noopener noreferrer"
            className="star-link"
            style={{
              display: "inline-flex",
              alignItems: "stretch",
              textDecoration: "none",
              border: "2.5px solid var(--page-border)",
              fontFamily: "var(--font-sans)",
              overflow: "hidden",
            }}
          >
            {/* Left: icon + label */}
            <span style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 8,
              padding: "8px 14px",
              fontSize: "13px",
              fontWeight: 700,
              color: "var(--page-text)",
              background: "var(--bg-paper)",
            }}>
              <svg width="16" height="16" viewBox="0 0 98 96" fill="currentColor" aria-hidden="true">
                <path fillRule="evenodd" clipRule="evenodd" d="M48.854 0C21.839 0 0 22 0 49.217c0 21.756 13.993 40.172 33.405 46.69 2.427.49 3.316-1.059 3.316-2.362 0-1.141-.08-5.052-.08-9.127-13.59 2.934-16.42-5.867-16.42-5.867-2.184-5.704-5.42-7.17-5.42-7.17-4.448-3.015.324-3.015.324-3.015 4.934.326 7.523 5.052 7.523 5.052 4.367 7.496 11.404 5.378 14.235 4.074.404-3.178 1.699-5.378 3.074-6.6-10.839-1.141-22.243-5.378-22.243-24.283 0-5.378 1.94-9.778 5.014-13.2-.485-1.222-2.184-6.275.486-13.038 0 0 4.125-1.304 13.426 5.052a46.97 46.97 0 0 1 12.214-1.63c4.125 0 8.33.571 12.213 1.63 9.302-6.356 13.427-5.052 13.427-5.052 2.67 6.763.97 11.816.485 13.038 3.155 3.422 5.015 7.822 5.015 13.2 0 18.905-11.404 23.06-22.324 24.283 1.78 1.548 3.316 4.481 3.316 9.126 0 6.6-.08 11.897-.08 13.526 0 1.304.89 2.853 3.316 2.364 19.412-6.52 33.405-24.935 33.405-46.691C97.707 22 75.788 0 48.854 0z"/>
              </svg>
              Star on GitHub
            </span>
            {/* Divider */}
            <span style={{ width: 2, background: "var(--page-border)", flexShrink: 0 }} aria-hidden="true" />
            {/* Right: star count */}
            <span style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 5,
              padding: "8px 12px",
              fontSize: "13px",
              fontWeight: 700,
              color: SLATE,
              background: "var(--bg-paper)",
              fontFamily: "var(--font-mono)",
            }}>
              ★ {starCount !== null ? (starCount >= 1000 ? `${(starCount / 1000).toFixed(1)}k` : starCount) : "—"}
            </span>
          </a>
        </div>
      </section>

      {/* RECENT CHATS — only if savedChats.length > 0 */}
      {savedChats.length > 0 && (
        <section style={{ padding: "40px 24px", background: "var(--page-bg)", borderTop: "2.5px solid var(--page-border)" }}>
          <div style={{ maxWidth: 900, margin: "0 auto" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
              <p style={{ fontFamily: "var(--font-mono)", fontSize: "11px", textTransform: "uppercase", letterSpacing: "0.1em", color: "var(--page-text-muted)" }}>
                Recent chats
              </p>
              <button
                onClick={handleDeleteAllSavedChats}
                style={{ fontSize: "11px", color: "var(--page-text-muted)", background: "none", border: "none", cursor: "pointer", textDecoration: "underline", fontFamily: "var(--font-mono)" }}
              >
                Clear all
              </button>
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {savedChats.slice(0, 5).map((chat) => (
                <div
                  key={chat.id}
                  role="button"
                  tabIndex={0}
                  onClick={() => handleOpenSavedChat(chat)}
                  onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") handleOpenSavedChat(chat); }}
                  style={{ display: "flex", alignItems: "center", gap: 12, padding: "12px 16px", background: "var(--bg-paper)", border: "2.5px solid var(--page-border)", cursor: "pointer", transition: "transform 0.1s ease, box-shadow 0.1s ease", boxShadow: "var(--shadow-subtle)" }}
                  onMouseEnter={(e) => {
                    const el = e.currentTarget as HTMLDivElement;
                    el.style.transform = "translate(-2px, -2px)";
                    el.style.boxShadow = SHADOW_1;
                  }}
                  onMouseLeave={(e) => {
                    const el = e.currentTarget as HTMLDivElement;
                    el.style.transform = "";
                    el.style.boxShadow = "var(--shadow-subtle)";
                  }}
                >
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.8rem", fontWeight: 600, color: "var(--page-text)", flexShrink: 0 }}>
                    {chat.owner}/{chat.repo}
                  </span>
                  <span style={{ fontSize: "0.75rem", color: "var(--page-text-dim)", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "var(--font-sans)" }}>
                    {chat.label} · {chat.messageCount} msg{chat.messageCount === 1 ? "" : "s"}
                  </span>
                  <button
                    onClick={(e) => { e.stopPropagation(); handleDeleteSavedChat(chat); }}
                    style={{ fontSize: "11px", color: "var(--page-text-muted)", background: "none", border: "none", cursor: "pointer", flexShrink: 0, fontFamily: "var(--font-mono)" }}
                  >
                    Delete
                  </button>
                </div>
              ))}
            </div>
          </div>
        </section>
      )}

      {/* EXAMPLE REPOS */}
      <section style={{ padding: "60px 24px", background: "var(--page-bg)", borderTop: "2.5px solid var(--page-border)" }}>
        <div style={{ maxWidth: 900, margin: "0 auto" }}>
          <p style={{ fontFamily: "var(--font-mono)", fontSize: "11px", textTransform: "uppercase", letterSpacing: "0.1em", color: "var(--page-text-muted)", marginBottom: 24 }}>
            Try an example repo
          </p>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 16 }}>
            {EXAMPLE_REPOSITORIES.map(({ owner, repo }) => (
              <button
                key={`${owner}/${repo}`}
                onClick={() => router.push(`/${owner}/${repo}`)}
                style={{
                  display: "flex",
                  flexDirection: "column",
                  alignItems: "flex-start",
                  gap: 10,
                  padding: "20px 24px",
                  background: "var(--bg-paper)",
                  border: "2.5px solid var(--page-border)",
                  boxShadow: "var(--shadow-subtle)",
                  cursor: "pointer",
                  textAlign: "left",
                  fontFamily: "inherit",
                  transition: "transform 0.1s, box-shadow 0.1s",
                }}
                onMouseEnter={(e) => {
                  const el = e.currentTarget as HTMLButtonElement;
                  el.style.transform = "translate(-2px,-2px)";
                  el.style.boxShadow = SHADOW_1;
                }}
                onMouseLeave={(e) => {
                  const el = e.currentTarget as HTMLButtonElement;
                  el.style.transform = "";
                  el.style.boxShadow = "var(--shadow-subtle)";
                }}
              >
                <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.85rem", fontWeight: 600, color: "var(--page-text)" }}>
                  {owner}/<span style={{ color: SLATE }}>{repo}</span>
                </span>
                <span style={{ fontSize: "0.75rem", fontWeight: 700, color: SLATE, fontFamily: "var(--font-sans)", textTransform: "uppercase", letterSpacing: "0.04em" }}>Explore →</span>
              </button>
            ))}
          </div>
        </div>
      </section>

      {/* HOW IT WORKS + ARCHITECTURE — merged */}
      <section
        ref={howSectionRef}
        style={{
          padding: "80px 24px",
          background: "var(--page-bg)",
          borderTop: "2.5px solid var(--page-border)",
          opacity: isHowVisible ? 1 : 0,
          transform: isHowVisible ? "translateY(0)" : "translateY(20px)",
          transition: "opacity 0.5s ease, transform 0.5s ease",
        }}
      >
        <div style={{ maxWidth: 1100, margin: "0 auto" }}>
          <p style={{ fontFamily: "var(--font-mono)", fontSize: "11px", textTransform: "uppercase", letterSpacing: "0.1em", color: "var(--page-text-muted)", marginBottom: 16, textAlign: "center" }}>
            How it works
          </p>
          <h2 style={{ fontFamily: "var(--font-display)", fontWeight: 900, fontSize: "clamp(1.5rem, 4vw, 2.5rem)", color: "var(--page-text)", textAlign: "center", marginBottom: 48, textTransform: "uppercase", letterSpacing: "0.02em" }}>
            Under the Hood
          </h2>

          {/* Step cards */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 0, marginBottom: 64 }}>
            {[
              { num: "01", title: "Connect a source", desc: "Paste a GitHub URL, click a data source button, or upload a document." },
              { num: "02", title: "Index in your browser", desc: "AST chunking + embeddings. No server. Everything local on-device." },
              { num: "03", title: "Ask questions", desc: "Chat across all indexed sources simultaneously. Results cite real data." },
            ].map((step, i) => (
              <div key={step.num} style={{
                padding: "32px 28px",
                border: "2.5px solid var(--page-border)",
                borderRight: i < 2 ? "none" : "2.5px solid var(--page-border)",
                background: "var(--bg-paper)",
                boxShadow: i === 0 ? SHADOW_1 : "none",
              }}>
                <span style={{ fontFamily: "var(--font-display)", fontSize: "2.5rem", fontWeight: 900, color: "var(--page-text-muted)", display: "block", marginBottom: 12, letterSpacing: "0.02em" }}>{step.num}</span>
                <h3 style={{ fontFamily: "var(--font-display)", fontWeight: 900, fontSize: "1rem", marginBottom: 8, color: "var(--page-text)", textTransform: "uppercase", letterSpacing: "0.04em" }}>{step.title}</h3>
                <p style={{ fontSize: "0.875rem", color: "var(--page-text-dim)", lineHeight: 1.6, fontFamily: "var(--font-sans)" }}>{step.desc}</p>
              </div>
            ))}
          </div>

          {/* Architecture diagram */}
          <ArchitectureDiagram />
        </div>
      </section>

      {/* FOOTER */}
      <footer style={{ padding: "24px 40px", background: "var(--bg-paper)", borderTop: "2.5px solid var(--page-border)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span style={{ fontFamily: "var(--font-display)", fontWeight: 900, fontSize: "1rem", color: "var(--page-text-muted)", textTransform: "uppercase", letterSpacing: "0.05em" }}>SecAsk</span>
        <div style={{ display: "flex", gap: 16 }}>
          <a href="/ablation" style={{ fontSize: "12px", color: "var(--page-text-muted)", textDecoration: "none", fontFamily: "var(--font-mono)" }}>Ablation</a>
          <a href="/metrics" style={{ fontSize: "12px", color: "var(--page-text-muted)", textDecoration: "none", fontFamily: "var(--font-mono)" }}>Metrics</a>
          <a href="https://github.com/FloareDor/gitask" target="_blank" rel="noopener noreferrer" style={{ fontSize: "12px", color: "var(--page-text-muted)", textDecoration: "none", fontFamily: "var(--font-mono)" }}>GitHub</a>
        </div>
      </footer>
    </div>
  );
}
