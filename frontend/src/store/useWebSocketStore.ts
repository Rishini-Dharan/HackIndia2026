/**
 * Q-Guardian OS — WebSocket Zustand Store
 *
 * Manages the WebSocket connection, chat messages, mounted widgets,
 * and real-time telemetry buffer. Handles auto-reconnect with
 * exponential backoff.
 */

import { create } from 'zustand'

// ── Types ────────────────────────────────────────────────────────

export interface ChatMessage {
  id: string
  type: 'chat'
  role: 'user' | 'agent'
  content: string
  timestamp: number
  widgets?: WidgetDescriptor[]
}

export interface WidgetDescriptor {
  id: string
  component: string
  props: Record<string, unknown>
  mountedAt: number
}

export interface TelemetryEvent {
  ts: string
  src_ip: string
  dst_ip: string
  protocol: string
  port: number
  bytes: number
  severity: 'low' | 'medium' | 'high' | 'critical'
  is_threat: boolean
  attack_type: string | null
  score: number
}

interface WebSocketState {
  socket: WebSocket | null
  isConnected: boolean
  sessionId: string | null
  messages: ChatMessage[]
  mountedWidgets: WidgetDescriptor[]
  telemetryBuffer: TelemetryEvent[]
  isTyping: boolean

  connect: (url?: string) => void
  disconnect: () => void
  sendMessage: (content: string) => void
  sendAction: (payload: Record<string, unknown>) => void
  dismissWidget: (widgetId: string) => void
  clearMessages: () => void
}

// ── Constants ────────────────────────────────────────────────────

const MAX_TELEMETRY_BUFFER = 120
const MAX_RECONNECT_DELAY = 10000
const DEFAULT_WS_URL = 'ws://localhost:8000/ws/chat'

let reconnectAttempts = 0
let reconnectTimer: ReturnType<typeof setTimeout> | null = null

function generateId(): string {
  return Math.random().toString(36).substring(2, 10)
}

// ── Store ────────────────────────────────────────────────────────

export const useWebSocketStore = create<WebSocketState>((set, get) => ({
  socket: null,
  isConnected: false,
  sessionId: null,
  messages: [],
  mountedWidgets: [],
  telemetryBuffer: [],
  isTyping: false,

  connect: (url?: string) => {
    const wsUrl = url || DEFAULT_WS_URL
    const existing = get().socket
    if (existing && existing.readyState === WebSocket.OPEN) return

    const ws = new WebSocket(wsUrl)

    ws.onopen = () => {
      console.log('[WS] Connected')
      reconnectAttempts = 0
      set({ socket: ws, isConnected: true })
    }

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data)
        const state = get()

        switch (data.type) {
          case 'chat': {
            const msg: ChatMessage = {
              id: generateId(),
              type: 'chat',
              role: data.role || 'agent',
              content: data.content || '',
              timestamp: Date.now(),
            }
            set({ messages: [...state.messages, msg], isTyping: false })
            break
          }

          case 'widget': {
            if (data.action === 'mount') {
              const widget: WidgetDescriptor = {
                id: data.id || generateId(),
                component: data.component,
                props: data.props || {},
                mountedAt: Date.now(),
              }

              // Attach widget to the last agent message, or create a standalone entry
              const msgs = [...state.messages]
              const lastAgentIdx = msgs.findLastIndex((m: ChatMessage) => m.role === 'agent')

              if (lastAgentIdx >= 0) {
                const lastMsg = { ...msgs[lastAgentIdx] }
                lastMsg.widgets = [...(lastMsg.widgets || []), widget]
                msgs[lastAgentIdx] = lastMsg
              }

              set({
                messages: msgs,
                mountedWidgets: [...state.mountedWidgets, widget],
              })
            } else if (data.action === 'unmount') {
              set({
                mountedWidgets: state.mountedWidgets.filter(w => w.id !== data.id),
              })
            }
            break
          }

          case 'telemetry': {
            const event = data.data as TelemetryEvent
            const buf = [...state.telemetryBuffer, event]
            if (buf.length > MAX_TELEMETRY_BUFFER) {
              buf.splice(0, buf.length - MAX_TELEMETRY_BUFFER)
            }
            set({ telemetryBuffer: buf })
            break
          }
        }
      } catch (e) {
        console.error('[WS] Parse error:', e)
      }
    }

    ws.onclose = () => {
      console.log('[WS] Disconnected')
      set({ socket: null, isConnected: false })

      // Auto-reconnect with exponential backoff
      const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), MAX_RECONNECT_DELAY)
      reconnectAttempts++
      console.log(`[WS] Reconnecting in ${delay}ms (attempt ${reconnectAttempts})`)

      if (reconnectTimer) clearTimeout(reconnectTimer)
      reconnectTimer = setTimeout(() => {
        get().connect(wsUrl)
      }, delay)
    }

    ws.onerror = (err) => {
      console.error('[WS] Error:', err)
    }

    set({ socket: ws })
  },

  disconnect: () => {
    if (reconnectTimer) {
      clearTimeout(reconnectTimer)
      reconnectTimer = null
    }
    const ws = get().socket
    if (ws) ws.close()
    set({ socket: null, isConnected: false })
  },

  sendMessage: (content: string) => {
    const { socket, messages } = get()
    if (!socket || socket.readyState !== WebSocket.OPEN) return

    // Add user message to chat
    const msg: ChatMessage = {
      id: generateId(),
      type: 'chat',
      role: 'user',
      content,
      timestamp: Date.now(),
    }
    set({ messages: [...messages, msg], isTyping: true })

    // Send to backend
    socket.send(JSON.stringify({ type: 'chat', content }))
  },

  sendAction: (payload: Record<string, unknown>) => {
    const { socket } = get()
    if (!socket || socket.readyState !== WebSocket.OPEN) return
    socket.send(JSON.stringify({ type: 'action', payload }))
  },

  dismissWidget: (widgetId: string) => {
    const { mountedWidgets, socket } = get()
    set({ mountedWidgets: mountedWidgets.filter(w => w.id !== widgetId) })

    if (socket && socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({
        type: 'action',
        payload: { action: 'dismiss_widget', id: widgetId },
      }))
    }
  },

  clearMessages: () => {
    set({ messages: [], mountedWidgets: [] })
    const { socket } = get()
    if (socket && socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({
        type: 'action',
        payload: { action: 'clear_memory' }
      }))
    }
  },
}))
