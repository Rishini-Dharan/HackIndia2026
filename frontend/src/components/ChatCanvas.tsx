/**
 * Q-Guardian OS — Chat Canvas Component
 *
 * Renders the conversational interface with user messages (right),
 * agent messages (left), and dynamically mounted widgets inline.
 */

import { useRef, useEffect, useState } from 'react'
import { useWebSocketStore, type ChatMessage } from '../store/useWebSocketStore'
import WidgetRenderer from './WidgetRenderer'
import { Send, Zap } from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'

export default function ChatCanvas() {
  const messages = useWebSocketStore(s => s.messages)
  const isConnected = useWebSocketStore(s => s.isConnected)
  const isTyping = useWebSocketStore(s => s.isTyping)
  const sendMessage = useWebSocketStore(s => s.sendMessage)

  const [input, setInput] = useState('')
  const scrollRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  // Auto-scroll to bottom on new messages
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [messages, isTyping])

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    const text = input.trim()
    if (!text || !isConnected) return
    sendMessage(text)
    setInput('')
    inputRef.current?.focus()
  }

  return (
    <div className="flex flex-col h-full">
      {/* Header Bar */}
      <header className="shrink-0 px-6 py-3 border-b border-border bg-abyss/80 backdrop-blur-sm flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Zap className="w-4 h-4 text-cyan" />
          <h2 className="text-sm font-semibold text-text">AI Investigation Operating System</h2>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[10px] font-mono text-text-dim px-2 py-0.5 rounded bg-deep border border-border">
            {messages.length} messages
          </span>
        </div>
      </header>

      {/* Messages Area */}
      <div
        ref={scrollRef}
        className="flex-1 overflow-y-auto px-6 py-4 space-y-4 scroll-smooth"
      >
        <AnimatePresence initial={false}>
          {messages.length === 0 && (
            <motion.div 
              key="empty-state"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="h-full"
            >
              <EmptyState />
            </motion.div>
          )}

          {messages.map((msg) => (
            <motion.div
              key={msg.id}
              initial={{ opacity: 0, y: 10, scale: 0.98 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              transition={{ type: 'spring', stiffness: 400, damping: 25 }}
            >
              <MessageBubble message={msg} />
            </motion.div>
          ))}

          {isTyping && (
            <motion.div
              key="typing-indicator"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.9 }}
              className="msg-agent flex justify-start"
            >
              <div className="glass-card px-4 py-3 max-w-md">
                <div className="flex items-center gap-1.5">
                  <span className="typing-dot" />
                  <span className="typing-dot" />
                  <span className="typing-dot" />
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Input Bar */}
      <form
        onSubmit={handleSubmit}
        className="shrink-0 px-4 py-3 border-t border-border bg-abyss relative z-10"
      >
        <div className="flex gap-3 items-center">
          <div className="flex-1 relative">
            <input
              ref={inputRef}
              type="text"
              value={input}
              onChange={e => setInput(e.target.value)}
              placeholder={isConnected ? 'Ask Q-Guardian... (try "show live traffic")' : 'Connecting...'}
              disabled={!isConnected}
              className="
                w-full px-4 py-3 rounded-xl
                bg-deep border border-border
                text-sm text-text placeholder:text-text-dim
                focus:outline-none focus:border-cyan/40 focus:ring-1 focus:ring-cyan/20
                transition-all duration-200
                disabled:opacity-40 disabled:cursor-not-allowed
                font-sans
              "
            />
          </div>
          <button
            type="submit"
            disabled={!isConnected || !input.trim()}
            className="
              w-11 h-11 rounded-xl
              bg-gradient-to-br from-cyan to-blue
              flex items-center justify-center
              text-void font-bold
              hover:shadow-lg hover:shadow-cyan/25
              active:scale-95
              transition-all duration-200
              disabled:opacity-30 disabled:cursor-not-allowed disabled:hover:shadow-none
              cursor-pointer
            "
          >
            <Send className="w-4 h-4" />
          </button>
        </div>
      </form>
    </div>
  )
}

function MessageBubble({ message }: { message: ChatMessage }) {
  const isUser = message.role === 'user'
  const activeWorkspace = useWebSocketStore((s) => s.activeWorkspace)

  return (
    <div className="space-y-3">
      <div className={`flex ${isUser ? 'justify-end msg-user' : 'justify-start msg-agent'}`}>
        <div
          className={`
            max-w-2xl rounded-2xl px-4 py-3 text-sm leading-relaxed
            ${isUser
              ? 'bg-gradient-to-br from-cyan/15 to-blue/10 border border-cyan/20 text-text'
              : 'glass-card text-text'
            }
          `}
        >
          <FormattedContent content={message.content} />
        </div>
      </div>

      {/* Render inline widgets attached to this message (only if not in split workspace) */}
      {!activeWorkspace && message.widgets && message.widgets.length > 0 && (
        <div className="space-y-3 pl-0">
          {message.widgets.map(widget => (
            <div key={widget.id} className="widget-enter">
              <WidgetRenderer descriptor={widget} />
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function FormattedContent({ content }: { content: string }) {
  // Simple markdown-like formatting for bold and line breaks
  const lines = content.split('\n')

  return (
    <div className="space-y-1">
      {lines.map((line, i) => {
        if (!line.trim()) return <br key={i} />

        // Process bold markers
        const parts = line.split(/(\*\*[^*]+\*\*)/g)
        return (
          <p key={i} className="leading-relaxed">
            {parts.map((part, j) => {
              if (part.startsWith('**') && part.endsWith('**')) {
                return <strong key={j} className="font-semibold text-cyan">{part.slice(2, -2)}</strong>
              }
              // Process inline code
              const codeParts = part.split(/(`[^`]+`)/g)
              return codeParts.map((cp, k) => {
                if (cp.startsWith('`') && cp.endsWith('`')) {
                  return (
                    <code key={`${j}-${k}`} className="px-1.5 py-0.5 rounded bg-deep text-cyan text-xs font-mono">
                      {cp.slice(1, -1)}
                    </code>
                  )
                }
                return <span key={`${j}-${k}`}>{cp}</span>
              })
            })}
          </p>
        )
      })}
    </div>
  )
}

function EmptyState() {
  return (
    <div className="flex flex-col items-center justify-center h-full text-center px-4 opacity-60">
      <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-cyan/10 to-blue/10 border border-cyan/15 flex items-center justify-center mb-4">
        <Zap className="w-7 h-7 text-cyan" />
      </div>
      <h3 className="text-base font-semibold text-text mb-2">Q-Guardian OS</h3>
      <p className="text-sm text-text-muted max-w-sm leading-relaxed">
        Your AI Investigation Operating System. Ask me to recover active threat cases, analyze logs, or orchestrate containment workspaces.
      </p>
      <div className="flex flex-wrap gap-2 mt-4 justify-center">
        {['Show live traffic', 'Analyze threats', 'Dashboard summary'].map(q => (
          <SuggestionChip key={q} text={q} />
        ))}
      </div>
    </div>
  )
}

function SuggestionChip({ text }: { text: string }) {
  const sendMessage = useWebSocketStore(s => s.sendMessage)
  const isConnected = useWebSocketStore(s => s.isConnected)

  return (
    <button
      onClick={() => isConnected && sendMessage(text)}
      disabled={!isConnected}
      className="
        px-3 py-1.5 rounded-full text-xs font-medium
        border border-cyan/20 text-cyan/70
        hover:bg-cyan/5 hover:text-cyan hover:border-cyan/40
        transition-all duration-200
        disabled:opacity-30 disabled:cursor-not-allowed
        cursor-pointer
      "
    >
      {text}
    </button>
  )
}
