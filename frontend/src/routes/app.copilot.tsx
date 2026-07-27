import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import { apiStream, ApiError } from "@/lib/api";
import { PageHeader, EmptyState } from "@/components/common";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent } from "@/components/ui/card";
import { Bot, Send, Trash2, User } from "lucide-react";
import { toast } from "sonner";

export const Route = createFileRoute("/app/copilot")({ component: CopilotPage });

type Msg = { id?: string; role: "user" | "assistant"; content: string; created_at?: string };

function CopilotPage() {
  const [messages, setMessages] = useState<Msg[]>([]);
  const [input, setInput] = useState("");
  const [streaming, setStreaming] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, streaming]);

  async function send() {
    const text = input.trim();
    if (!text || streaming) return;
    const history = messages.map(({ role, content }) => ({ role, content }));
    setInput("");
    setMessages((m) => [...m, { role: "user", content: text }, { role: "assistant", content: "" }]);
    setStreaming(true);
    try {
      await apiStream("/copilot/chat", { message: text, history }, (chunk) => {
        setMessages((m) => {
          const copy = [...m];
          copy[copy.length - 1] = {
            ...copy[copy.length - 1],
            content: copy[copy.length - 1].content + chunk,
          };
          return copy;
        });
      });
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : "Chat failed");
      setMessages((m) => {
        const copy = [...m];
        if (copy[copy.length - 1]?.role === "assistant" && !copy[copy.length - 1].content)
          copy.pop();
        return copy;
      });
    } finally {
      setStreaming(false);
    }
  }

  function clearHistory() {
    setMessages([]);
  }

  return (
    <>
      <PageHeader
        title="AI Copilot"
        description="Ask about your security posture, threats, or best practices."
        actions={
          <Button size="sm" variant="outline" onClick={clearHistory} disabled={!messages.length}>
            <Trash2 className="mr-1 h-4 w-4" /> Clear history
          </Button>
        }
      />
      <Card className="flex h-[calc(100vh-14rem)] flex-col">
        <CardContent className="flex flex-1 flex-col gap-2 overflow-hidden p-4">
          <div className="flex-1 space-y-4 overflow-y-auto pr-2">
            {!messages.length ? (
              <EmptyState
                title="Start the conversation."
                description="Try: 'What are the top risks on my account right now?'"
                icon={<Bot className="h-6 w-6" />}
              />
            ) : (
              messages.map((m, i) => (
                <div
                  key={m.id ?? i}
                  className={m.role === "user" ? "flex justify-end" : "flex justify-start"}
                >
                  <div
                    className={`flex max-w-[85%] gap-2 rounded-2xl px-4 py-2 text-sm ${m.role === "user" ? "bg-primary text-primary-foreground" : "border border-border bg-muted/40"}`}
                  >
                    <div className="mt-0.5 shrink-0 opacity-70">
                      {m.role === "user" ? (
                        <User className="h-3.5 w-3.5" />
                      ) : (
                        <Bot className="h-3.5 w-3.5" />
                      )}
                    </div>
                    <div className="min-w-0">
                      {m.role === "assistant" ? (
                        <FormattedCopilotMessage
                          content={m.content || (streaming && i === messages.length - 1 ? "…" : "")}
                        />
                      ) : (
                        <div className="whitespace-pre-wrap break-words">{m.content}</div>
                      )}
                    </div>
                  </div>
                </div>
              ))
            )}
            <div ref={bottomRef} />
          </div>
          <form
            className="mt-2 flex items-end gap-2 border-t border-border pt-3"
            onSubmit={(e) => {
              e.preventDefault();
              send();
            }}
          >
            <Textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Ask a question…"
              rows={2}
              className="resize-none"
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  send();
                }
              }}
            />
            <Button type="submit" disabled={!input.trim() || streaming}>
              <Send className="h-4 w-4" />
            </Button>
          </form>
        </CardContent>
      </Card>
    </>
  );
}

function FormattedCopilotMessage({ content }: { content: string }) {
  const lines = content.replace(/\r\n/g, "\n").split("\n");
  return (
    <div className="space-y-2 break-words leading-relaxed">
      {lines.map((line, index) => {
        const trimmed = line.trim();
        if (!trimmed) return <div key={index} className="h-1" />;
        const heading = trimmed.match(/^#{1,3}\s+(.+)$/);
        if (heading)
          return (
            <div key={index} className="pt-1 font-semibold text-foreground">
              {renderInlineMarkdown(heading[1])}
            </div>
          );
        const ordered = trimmed.match(/^(\d+)\.\s+(.+)$/);
        if (ordered)
          return (
            <div key={index} className="grid grid-cols-[1.25rem_minmax(0,1fr)] gap-1">
              <span className="font-semibold text-primary">{ordered[1]}.</span>
              <span>{renderInlineMarkdown(ordered[2])}</span>
            </div>
          );
        const bullet = trimmed.match(/^[-*]\s+(.+)$/);
        if (bullet)
          return (
            <div key={index} className="grid grid-cols-[0.75rem_minmax(0,1fr)] gap-1">
              <span className="text-primary">•</span>
              <span>{renderInlineMarkdown(bullet[1])}</span>
            </div>
          );
        return <p key={index}>{renderInlineMarkdown(trimmed)}</p>;
      })}
    </div>
  );
}

function renderInlineMarkdown(text: string) {
  return text
    .split(/(\*\*[^*]+\*\*)/g)
    .filter(Boolean)
    .map((part, index) =>
      part.startsWith("**") && part.endsWith("**") ? (
        <strong key={index}>{part.slice(2, -2)}</strong>
      ) : (
        <span key={index}>{part}</span>
      ),
    );
}
