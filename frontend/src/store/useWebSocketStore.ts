/**
 * Q-Guardian OS — WebSocket & Sandbox Mock Zustand Store
 *
 * Manages the WebSocket connection, chat messages, mounted widgets,
 * and real-time telemetry buffer. Handles auto-reconnect with
 * exponential backoff, and automatically falls back to a fully interactive
 * client-side Sandbox Mock Mode if the backend is not running (e.g. when hosted).
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

export interface InvestigationWorkspace {
  id: string
  title: string
  threatType: string
  confidence: number
  hypothesis: string
  evidence: string[]
  layout: WidgetDescriptor[]
}

interface WebSocketState {
  socket: WebSocket | null
  isConnected: boolean
  sessionId: string | null
  messages: ChatMessage[]
  mountedWidgets: WidgetDescriptor[]
  telemetryBuffer: TelemetryEvent[]
  activeWorkspace: InvestigationWorkspace | null
  isTyping: boolean
  blockedIps: Set<string>
  isSimulating: boolean
  isMockMode: boolean

  connect: (url?: string) => void
  disconnect: () => void
  sendMessage: (content: string) => void
  sendAction: (payload: Record<string, unknown>) => void
  dismissWidget: (widgetId: string) => void
  clearMessages: () => void
  triggerDemoStage: (stage: string) => void
}

// ── Constants ────────────────────────────────────────────────────

const MAX_TELEMETRY_BUFFER = 120
const MAX_RECONNECT_DELAY = 10000
const DEFAULT_WS_URL = 'ws://localhost:8000/ws/chat'

let reconnectAttempts = 0
let reconnectTimer: ReturnType<typeof setTimeout> | null = null
let mockTelemetryTimer: ReturnType<typeof setInterval> | null = null

function generateId(): string {
  return Math.random().toString(36).substring(2, 10)
}

// ── Realistic Mock Traffic Generator ─────────────────────────────

const PROTOCOL_PROFILES: Record<string, { weight: number; ports: number[]; byte_range: [number, number]; threat_capable: boolean }> = {
  HTTPS: { weight: 35, ports: [443, 8443],       byte_range: [200, 1500],  threat_capable: false },
  HTTP:  { weight: 20, ports: [80, 8080, 8000],  byte_range: [500, 4000],  threat_capable: true },
  DNS:   { weight: 20, ports: [53],               byte_range: [64, 512],    threat_capable: true },
  TCP:   { weight: 10, ports: [3306, 5432, 6379], byte_range: [100, 2000],  threat_capable: true },
  SSH:   { weight: 5,  ports: [22],               byte_range: [64, 256],    threat_capable: true },
  ICMP:  { weight: 5,  ports: [0],                byte_range: [64, 128],    threat_capable: false },
  UDP:   { weight: 5,  ports: [123, 514, 1194],   byte_range: [64, 1000],   threat_capable: false },
}

const INTERNAL_SUBNETS = [
  ["192.168.1", 40],
  ["192.168.2", 15],
  ["10.0.1", 20],
  ["10.0.2", 10],
  ["172.16.0", 10],
  ["172.16.5", 5],
]

const EXTERNAL_SUBNETS = [
  ["104.26.10", 15],
  ["142.250.80", 15],
  ["13.107.42", 10],
  ["151.101.1", 10],
  ["203.0.113", 5],
  ["45.33.32", 5],
]

function randomIp(subnets: any[]) {
  const total = subnets.reduce((s, x) => s + x[1], 0)
  let r = Math.random() * total
  let chosen = subnets[0][0]
  for (const [net, w] of subnets) {
    r -= w
    if (r <= 0) {
      chosen = net
      break
    }
  }
  return `${chosen}.${Math.floor(Math.random() * 254) + 1}`
}

function generateBaselineEvent() {
  const protos = Object.keys(PROTOCOL_PROFILES)
  const weights = protos.map(p => PROTOCOL_PROFILES[p].weight)
  const total = weights.reduce((s, x) => s + x, 0)
  let r = Math.random() * total
  let proto_name = protos[0]
  for (let i = 0; i < protos.length; i++) {
    r -= weights[i]
    if (r <= 0) {
      proto_name = protos[i]
      break
    }
  }
  const profile = PROTOCOL_PROFILES[proto_name]
  const src_ip = Math.random() < 0.7 ? randomIp(INTERNAL_SUBNETS) : randomIp(EXTERNAL_SUBNETS)
  const dst_ip = Math.random() < 0.7 ? randomIp(EXTERNAL_SUBNETS) : randomIp(INTERNAL_SUBNETS)
  let base_bytes = Math.floor(Math.random() * (profile.byte_range[1] - profile.byte_range[0])) + profile.byte_range[0]
  if (Math.random() < 0.1) {
    base_bytes = Math.floor(base_bytes * (2.0 + Math.random() * 3.0))
  }
  const severities = ["low", "medium", "high", "critical"]
  const sevWeights = [0.70, 0.25, 0.04, 0.01]
  let r2 = Math.random()
  let severity = "low"
  for (let i = 0; i < severities.length; i++) {
    r2 -= sevWeights[i]
    if (r2 <= 0) {
      severity = severities[i]
      break
    }
  }
  const is_threat = (severity === "high" || severity === "critical") && profile.threat_capable && Math.random() < 0.15
  return {
    ts: new Date().toISOString(),
    src_ip,
    dst_ip,
    protocol: proto_name,
    port: profile.ports[Math.floor(Math.random() * profile.ports.length)],
    bytes: base_bytes,
    severity: severity as any,
    is_threat,
    attack_type: is_threat ? ["DDoS", "SQLi", "XSS", "BruteForce"][Math.floor(Math.random() * 4)] : null,
    score: is_threat ? Number((0.6 + Math.random() * 0.25).toFixed(3)) : Number((Math.random() * 0.2).toFixed(3)),
  }
}

let proactiveTriggered = false
let mitigationTime: number | null = null
const dampeningDuration = 5000 // 5 seconds

function generateAttackEvent(blockedIps: Set<string>) {
  const src_ip = "45.33.12.99"
  if (blockedIps.has(src_ip)) {
    if (mitigationTime !== null) {
      const elapsed = Date.now() - mitigationTime
      if (elapsed < dampeningDuration) {
        const threat_chance = Math.max(0.0, 1.0 - (elapsed / dampeningDuration))
        if (Math.random() > threat_chance) {
          return generateBaselineEvent()
        }
      } else {
        return generateBaselineEvent()
      }
    } else {
      return generateBaselineEvent()
    }
  }
  return {
    ts: new Date().toISOString(),
    src_ip,
    dst_ip: "192.168.1.10",
    protocol: "TCP",
    port: 445,
    bytes: Math.floor(Math.random() * (65535 - 30000)) + 30000,
    severity: "critical" as const,
    is_threat: true,
    attack_type: "Ransomware",
    score: Number((0.95 + Math.random() * 0.049).toFixed(3)),
  }
}

// ── Store ────────────────────────────────────────────────────────

export const useWebSocketStore = create<WebSocketState>((set, get) => {
  
  // Start local mock interval for telemetry events
  function startMockTelemetryLoop() {
    if (mockTelemetryTimer) clearInterval(mockTelemetryTimer)
    mockTelemetryTimer = setInterval(() => {
      const state = get()
      if (!state.isMockMode) return

      let events: TelemetryEvent[] = []
      if (state.isSimulating) {
        // Attack Mode: 1 attack event + 1-2 baseline events
        const att = generateAttackEvent(state.blockedIps)
        events.push(att)
        const count = Math.floor(Math.random() * 2) + 1
        for (let i = 0; i < count; i++) {
          events.push(generateBaselineEvent())
        }

        // Proactive workspace mount on first threat event
        if (!proactiveTriggered && att.is_threat && !state.blockedIps.has(att.src_ip)) {
          proactiveTriggered = true
          
          setTimeout(() => {
            const currentWorkspace: InvestigationWorkspace = {
              id: "INV-412",
              title: "Ransomware Lateral Movement Case",
              threatType: "Ransomware",
              confidence: 98.0,
              hypothesis: "Compromised external endpoint (45.33.12.99) is pushing SMB lateral movement anomalies to encrypt network files.",
              evidence: [
                "Unusually high bytes transfer (65,535 bytes) on SMB port 445.",
                "Repeated connections from high-risk external subnet.",
                "Java high-speed packet ingestion classified: threat score = 0.985."
              ],
              layout: [
                {
                  id: "traffic-ransomware",
                  component: "LiveTrafficChart",
                  props: {
                    title: "Active Traffic Spike (Port 445)",
                    description: "Spike detected in Java ingestion packet logs"
                  },
                  mountedAt: Date.now()
                },
                {
                  id: "topology-ransomware",
                  component: "ThreatTopology",
                  props: {
                    title: "Ransomware Blast Radius",
                    nodes: [
                      { id: "45.33.12.99", type: "attacker", label: "45.33.12.99 (Attacker)", severity: "critical" },
                      { id: "192.168.1.10", type: "victim", label: "192.168.1.10 (Compromised)", severity: "high" },
                      { id: "192.168.1.1", type: "clean", label: "Gateway", severity: "low" }
                    ],
                    edges: [
                      { source: "45.33.12.99", target: "192.168.1.10", attackType: "Ransomware", bandwidth: 65535 }
                    ]
                  },
                  mountedAt: Date.now()
                },
                {
                  id: "mitigate-ransomware",
                  component: "MitigationAction",
                  props: {
                    title: "Containment Controls",
                    description: "Select isolation scope and execute block rules",
                    threatIps: ["45.33.12.99"],
                    attackType: "Ransomware",
                    severity: "critical",
                    blockDurationHours: 48,
                    scope: "global"
                  },
                  mountedAt: Date.now()
                }
              ]
            }

            const alertMsg: ChatMessage = {
              id: generateId(),
              type: 'chat',
              role: 'agent',
              content: "⚠️ **CRITICAL THREAT INTRUSION DETECTED**\n\nHigh-volume SMB anomalies detected. I have proactively instantiated investigation workspace **INV-412** and mounted the Threat Topology, Traffic Monitor, and Containment panels. Recommended action: Isolate host immediately.",
              timestamp: Date.now(),
              widgets: currentWorkspace.layout
            }

            set({
              activeWorkspace: currentWorkspace,
              mountedWidgets: currentWorkspace.layout,
              messages: [...get().messages, alertMsg]
            })
          }, 800)
        }
      } else {
        // Normal Mode: 2-4 baseline events
        const count = Math.floor(Math.random() * 3) + 2
        for (let i = 0; i < count; i++) {
          events.push(generateBaselineEvent())
        }
      }

      // Filter events from blocked IPs
      const filtered = events.filter(e => !(e.is_threat && state.blockedIps.has(e.src_ip)))
      
      const newBuf = [...state.telemetryBuffer, ...filtered]
      if (newBuf.length > MAX_TELEMETRY_BUFFER) {
        newBuf.splice(0, newBuf.length - MAX_TELEMETRY_BUFFER)
      }
      set({ telemetryBuffer: newBuf })
    }, 500)
  }

  function startLocalMockMode() {
    console.log('[WS] Falling back to browser Sandbox Mode')
    if (reconnectTimer) clearTimeout(reconnectTimer)
    
    set({
      isMockMode: true,
      isConnected: true, // Show connected indicator for sandbox
      socket: null
    })

    const sandboxMsg: ChatMessage = {
      id: generateId(),
      type: 'chat',
      role: 'agent',
      content: "🤖 **Local Sandbox Activated**\n\nI couldn't establish a connection to the Q-Guardian FastAPI backend at `ws://localhost:8000` (this usually happens if the backend is not running or when hosted statically).\n\nNo worries! I've loaded a fully interactive **client-side simulator** in your browser. \n\nYou can click **'Simulate Attack'** in the sidebar, watch telemetry stream, interact with me in chat (try asking to *'show live traffic'*, *'open triage board'*, *'show firewall rules'*), and execute the **Mitigation containment** rules!",
      timestamp: Date.now()
    }

    set({ messages: [...get().messages, sandboxMsg] })
    startMockTelemetryLoop()
  }

  return {
    socket: null,
    isConnected: false,
    sessionId: null,
    messages: [],
    mountedWidgets: [],
    telemetryBuffer: [],
    activeWorkspace: null,
    isTyping: false,
    blockedIps: new Set<string>(),
    isSimulating: false,
    isMockMode: false,

    connect: (url?: string) => {
      if (get().isMockMode) return // Already in mock sandbox mode!

      const wsUrl = url || DEFAULT_WS_URL
      const existing = get().socket
      if (existing && existing.readyState === WebSocket.OPEN) return

      try {
        const ws = new WebSocket(wsUrl)

        ws.onopen = () => {
          console.log('[WS] Connected')
          reconnectAttempts = 0
          set({ socket: ws, isConnected: true, isMockMode: false })
          if (mockTelemetryTimer) {
            clearInterval(mockTelemetryTimer)
            mockTelemetryTimer = null
          }
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

              case 'workspace_mount': {
                const ws = data.workspace as InvestigationWorkspace
                const widgets: WidgetDescriptor[] = (ws.layout || []).map((w: any) => ({
                  id: w.id || generateId(),
                  component: w.component,
                  props: w.props || {},
                  mountedAt: Date.now()
                }))
                
                set({
                  activeWorkspace: {
                    ...ws,
                    layout: widgets
                  },
                  mountedWidgets: widgets
                })
                break
              }

              case 'workspace_unmount': {
                set({
                  activeWorkspace: null,
                  mountedWidgets: []
                })
                break
              }

              case 'telemetry': {
                const event = data.data as TelemetryEvent
                if (event.is_threat && state.blockedIps.has(event.src_ip)) {
                  break
                }
                const buf = [...state.telemetryBuffer, event]
                if (buf.length > MAX_TELEMETRY_BUFFER) {
                  buf.splice(0, buf.length - MAX_TELEMETRY_BUFFER)
                }
                set({ telemetryBuffer: buf })
                break
              }

              case 'mitigation_applied': {
                const newBlocked = new Set(state.blockedIps)
                const mitigatedIps: string[] = data.blockedIps || []
                mitigatedIps.forEach((ip: string) => newBlocked.add(ip))

                const cleanedBuffer = state.telemetryBuffer.filter(
                  (evt: TelemetryEvent) => !(evt.is_threat && newBlocked.has(evt.src_ip))
                )

                set({
                  blockedIps: newBlocked,
                  telemetryBuffer: cleanedBuffer,
                })
                break
              }

              case 'simulation_stopped': {
                set({ isSimulating: false })
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

          if (get().isMockMode) return

          // Fallback to local sandbox mock mode immediately on first connection failure
          startLocalMockMode()
        }

        ws.onerror = (err) => {
          console.error('[WS] Error:', err)
        }

        set({ socket: ws })
      } catch (e) {
        console.error('[WS] Exception connecting:', e)
        if (!get().isMockMode) {
          startLocalMockMode()
        }
      }
    },

    disconnect: () => {
      if (reconnectTimer) {
        clearTimeout(reconnectTimer)
        reconnectTimer = null
      }
      if (mockTelemetryTimer) {
        clearInterval(mockTelemetryTimer)
        mockTelemetryTimer = null
      }
      const ws = get().socket
      if (ws) ws.close()
      set({ socket: null, isConnected: false, isMockMode: false })
    },

    sendMessage: (content: string) => {
      const { socket, messages, isMockMode } = get()
      
      const userMsg: ChatMessage = {
        id: generateId(),
        type: 'chat',
        role: 'user',
        content,
        timestamp: Date.now(),
      }
      set({ messages: [...messages, userMsg], isTyping: true })

      if (!isMockMode && socket && socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({ type: 'chat', content }))
        return
      }

      // Emulate Chat response in local mock mode
      setTimeout(() => {
        const s = content.toLowerCase()
        let reply = "Hello! I am Q-Guardian OS. I dynamically compile security dashboards. Try asking me to **'show live network traffic'**, **'analyze the threat topology'**, **'open triage board'**, or **'show firewall rules'**."
        let widget: WidgetDescriptor | null = null
        let newWorkspaceLayout: WidgetDescriptor[] | null = null

        if (anyKeyword(s, ["traffic", "monitor", "live", "stream", "packets", "bandwidth", "network"])) {
          reply = "📡 Mounting the live traffic monitor. Telemetry data is streaming in real-time."
          widget = {
            id: `traffic-${Math.floor(Math.random() * 9000) + 1000}`,
            component: "LiveTrafficChart",
            props: {
              title: "Live Network Traffic",
              description: "Real-time packet throughput across monitored interfaces"
            },
            mountedAt: Date.now()
          }
        } 
        else if (anyKeyword(s, ["threat", "topology", "blast", "attack", "map", "graph", "radius", "analyze", "analyse"])) {
          reply = "🔍 Detected 1 attacker node(s) targeting 1 server. Mounting the threat topology blast radius."
          widget = {
            id: `topology-${Math.floor(Math.random() * 9000) + 1000}`,
            component: "ThreatTopology",
            props: {
              title: "Attack Blast Radius",
              description: "Node-link visualization of active threat vectors",
              nodes: [
                { id: "45.33.12.99", type: "attacker", label: "45.33.12.99 (Attacker)", severity: "critical" },
                { id: "192.168.1.10", type: "victim", label: "192.168.1.10 (Compromised Host)", severity: "high" },
                { id: "192.168.1.1", type: "clean", label: "Gateway", severity: "low" }
              ],
              edges: [
                { source: "45.33.12.99", target: "192.168.1.10", attackType: "Ransomware", bandwidth: 65535 }
              ]
            },
            mountedAt: Date.now()
          }
        }
        else if (anyKeyword(s, ["triage", "summary", "board", "active threats", "incidents", "list"])) {
          reply = "📋 Fetching the current incident triage board."
          widget = {
            id: `triage-${Math.floor(Math.random() * 9000) + 1000}`,
            component: "IncidentTriageBoard",
            props: {
              title: "Incident Triage Board",
              description: "Active anomalies requiring operator attention"
            },
            mountedAt: Date.now()
          }
        }
        else if (anyKeyword(s, ["rule", "firewall", "blocked", "active blocks"])) {
          reply = "🔒 Querying active firewall rules in local memory..."
          const rows = get().blockedIps.size > 0 
            ? Array.from(get().blockedIps).map((ip, idx) => ({ id: `FW-${100+idx}`, ips: ip, strategy: "BLOCK", timestamp: "Active Ruleset" }))
            : [{ id: "N/A", ips: "No active IP blocks registered in local memory.", strategy: "NONE", timestamp: "N/A" }]

          widget = {
            id: `rules-${Math.floor(Math.random() * 9000) + 1000}`,
            component: "DynamicDashboard",
            props: {
              title: "Active Firewall Rules",
              description: "Currently enforced IP isolations",
              layoutType: "table",
              columns: [
                { key: "id", label: "Rule ID" },
                { key: "ips", label: "Isolated IPs" },
                { key: "strategy", label: "Strategy" },
                { key: "timestamp", label: "Status" }
              ],
              rows
            },
            mountedAt: Date.now()
          }
        }
        else if (anyKeyword(s, ["compare", "comparison", "investigate", "historical"])) {
          // Morph current workspace if active
          const active = get().activeWorkspace
          if (active) {
            const has_comp = active.layout.some(w => w.id === "comparison-widget")
            if (!has_comp) {
              const compWidget = {
                id: "comparison-widget",
                component: "DynamicDashboard",
                props: {
                  title: "Historical Baseline Comparison",
                  description: "Port 445 SMB comparison against yesterday's normal metrics",
                  layoutType: "cards",
                  data: [
                    { label: "Baseline Traffic", value: "12.4 KB/s", trend: "stable" },
                    { label: "Peak Ingress", value: "98.2 MB/s", trend: "critical" }
                  ]
                },
                mountedAt: Date.now()
              }
              newWorkspaceLayout = [...active.layout, compWidget]
              reply = "📊 **Analyzing historical baselines...** I have appended the **Historical Comparison** panel to your active workspace layout."
            } else {
              reply = "Historical Comparison panel is already active in your workspace."
            }
          } else {
            reply = "You can run comparison metrics once an active threat workspace is mounted (try clicking **'Simulate Attack'** first)."
          }
        }
        else if (anyKeyword(s, ["false positive", "legitimate", "admin"])) {
          const active = get().activeWorkspace
          if (active) {
            const revisedWorkspace: InvestigationWorkspace = {
              id: "INV-412",
              title: "Investigation Closed: Legitimate Admin Session (False Positive)",
              threatType: "False Positive",
              confidence: 0.0,
              hypothesis: "Initial SMB lateral movement alert was triggered by authorized admin task running backups.",
              evidence: [
                "Authorized administrative credentials (domain_admin_alex) used.",
                "Process parent hash verified against deployment baseline.",
                "Threat neutralized: classified as Legitimate Activity."
              ],
              layout: [
                {
                  id: "traffic-ransomware",
                  component: "LiveTrafficChart",
                  props: {
                    title: "Post-Mitigation Stable Traffic",
                    description: "Port 445 SMB bandwidth check",
                    mitigatedIps: Array.from(get().blockedIps)
                  },
                  mountedAt: Date.now()
                },
                {
                  id: "auth-timeline",
                  component: "DynamicDashboard",
                  props: {
                    title: "Active Authentication Logs",
                    description: "Verification history of domain_admin_alex credentials",
                    layoutType: "table",
                    columns: [
                      { key: "timestamp", label: "Timestamp" },
                      { key: "user", label: "User Principle" },
                      { key: "action", label: "Action Executed" },
                      { key: "status", label: "Auth Status" }
                    ],
                    rows: [
                      { timestamp: "15:38:12", user: "domain_admin_alex", action: "Kerberos Ticket Grant", status: "Granted" },
                      { timestamp: "15:39:05", user: "domain_admin_alex", action: "Remote Directory Sync", status: "Authorized" }
                    ]
                  },
                  mountedAt: Date.now()
                },
                {
                  id: "security-baselines",
                  component: "DynamicDashboard",
                  props: {
                    title: "Security Integrity Verification",
                    description: "Host configuration baselines",
                    layoutType: "cards",
                    data: [
                      { label: "Host Integrity", value: "100%", trend: "stable" },
                      { label: "Credential Status", value: "Valid Token", trend: "normal" }
                    ]
                  },
                  mountedAt: Date.now()
                }
              ]
            }
            set({
              activeWorkspace: revisedWorkspace,
              mountedWidgets: revisedWorkspace.layout
            })
            reply = "🕵️ **Hypothesis Revised & Resolved**\n\nUpon reviewing credential authorization hashes, I have verified that the SMB packets originated from `domain_admin_alex` during a scheduled backup synchronization.\n\nI have marked Case **INV-412** as a **False Positive (Legitimate Activity)** in local memory. I've re-composed the active workspace layout to replace security topology containment tools with the Authentication Verification timeline and Host Integrity panels."
          } else {
            reply = "There is no active case workspace to revise. Use **'Simulate Attack'** to mount a threat workspace first."
          }
        }
        else if (anyKeyword(s, ["hide graph", "hide topology"])) {
          const active = get().activeWorkspace
          if (active) {
            const filtered = active.layout.filter(w => w.component !== "ThreatTopology")
            set({
              activeWorkspace: { ...active, layout: filtered },
              mountedWidgets: filtered
            })
            reply = "👁️ **Workspace layout modified.** Hiding the network topology graph from active canvas."
          } else {
            reply = "No active topology to hide."
          }
        }
        else if (anyKeyword(s, ["generate report", "executive report", "report"])) {
          const active = get().activeWorkspace
          if (active) {
            const has_rep = active.layout.some(w => w.id === "report-widget")
            if (!has_rep) {
              const repWidget = {
                id: "report-widget",
                component: "DynamicDashboard",
                props: {
                  title: "Executive Incident Report",
                  description: "Auto-generated analysis for incident INV-412",
                  layoutType: "document",
                  blocks: [
                    { type: "title", content: "INCIDENT SUMMARY REPORT: INV-412" },
                    { type: "section", content: "1. Incident Overview" },
                    { type: "paragraph", content: "At 15:39 UTC, high-speed Java parsing logs flagged anomalous lateral movement traffic originating from high-risk external node 45.33.12.99. Target destination: Internal Server 192.168.1.10." },
                    { type: "section", content: "2. Mitigation & Remediation Actions" },
                    { type: "paragraph", content: "Operator executed immediate global isolation on the source endpoint. Outbound connections blocked. Post-mitigation metrics verified normal network levels." }
                  ]
                },
                mountedAt: Date.now()
              }
              newWorkspaceLayout = [...active.layout, repWidget]
              reply = "📝 **Compiling data logs...** I have generated the **Executive Incident Report** document widget and aligned it to your workspace grid."
            } else {
              reply = "Executive Report is already mounted in the workspace layout."
            }
          } else {
            reply = "Please initiate an active investigation first before requesting incident reports."
          }
        }

        const agentMsg: ChatMessage = {
          id: generateId(),
          type: 'chat',
          role: 'agent',
          content: reply,
          timestamp: Date.now()
        }

        if (widget) {
          agentMsg.widgets = [widget]
          set({
            messages: [...get().messages, agentMsg],
            mountedWidgets: [...get().mountedWidgets, widget],
            isTyping: false
          })
        } else if (newWorkspaceLayout) {
          const active = get().activeWorkspace!
          set({
            activeWorkspace: { ...active, layout: newWorkspaceLayout },
            mountedWidgets: newWorkspaceLayout,
            messages: [...get().messages, agentMsg],
            isTyping: false
          })
        } else {
          set({
            messages: [...get().messages, agentMsg],
            isTyping: false
          })
        }
      }, 600)
    },

    sendAction: (payload: Record<string, unknown>) => {
      const { socket, isMockMode } = get()
      
      if (!isMockMode && socket && socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({ type: 'action', payload }))
        return
      }

      // Emulate Actions in local mock sandbox
      const action = payload.action as string
      if (action === 'simulate_attack') {
        set({ isSimulating: true })
        // Proactive trigger reset
        proactiveTriggered = false
        mitigationTime = null
      } 
      else if (action === 'stop_simulation') {
        set({ isSimulating: false })
      } 
      else if (action === 'chat_command') {
        get().sendMessage((payload.command as string) || '')
      } 
      else if (action === 'unblock_ip') {
        const ips = (payload.ips as string[]) || []
        const nextBlocked = new Set(get().blockedIps)
        ips.forEach(ip => nextBlocked.delete(ip))
        set({ blockedIps: nextBlocked })
        
        // Broadcast confirmation
        setTimeout(() => {
          const unblockMsg: ChatMessage = {
            id: generateId(),
            type: 'chat',
            role: 'agent',
            content: `🔓 **Firewall Rule Removed**\n\n**IPs Restored:** ${ips.join(', ')}\n**Status:** Firewall rule updated. Traffic from this source is no longer blocked. Network state returning to standard monitoring.`,
            timestamp: Date.now()
          }
          set({ messages: [...get().messages, unblockMsg] })
        }, 600)
      }
      else if (action === 'isolate_ip') {
        const ips = (payload.ips as string[]) || []
        const strategy = (payload.strategy as string) || "block"
        const nextBlocked = new Set(get().blockedIps)
        ips.forEach(ip => nextBlocked.add(ip))
        
        mitigationTime = Date.now()
        
        // Flush threat telemetry from blocked IPs so chart drops immediately
        const cleanedBuffer = get().telemetryBuffer.filter(
          (evt: TelemetryEvent) => !(evt.is_threat && nextBlocked.has(evt.src_ip))
        )

        set({
          isSimulating: false,
          blockedIps: nextBlocked,
          telemetryBuffer: cleanedBuffer
        })

        // Send confirmation chat message
        setTimeout(() => {
          const confirmMsg: ChatMessage = {
            id: generateId(),
            type: 'chat',
            role: 'agent',
            content: `✅ **Mitigation Executed**\n\n**Strategy:** ${strategy.toUpperCase()}\n**IPs Isolated:** ${ips.join(', ')}\n**Status:** All firewall rules applied successfully.\n\nTraffic from these sources has been blocked. I have logged this containment status into local memory and marked case **INV-412** as neutralized.\n\n🔄 Recomposing workspace to post-mitigation monitoring view...`,
            timestamp: Date.now()
          }

          // Recompose workspace to post-mitigation dashboard layout
          const postMitigationWorkspace: InvestigationWorkspace = {
            id: "INV-412",
            title: "Post-Mitigation Monitoring — INV-412",
            threatType: "Ransomware (Neutralized)",
            confidence: 0.0,
            hypothesis: "Threat neutralized. Blocked attacker IPs and transitioning to baseline monitoring.",
            evidence: [
              `Mitigation strategy '${strategy}' applied to ${ips.length} IPs.`,
              "Attack mode disabled — simulator producing clean traffic only.",
              "Firewall propagation delay: ~5 seconds for full dampening."
            ],
            layout: [
              {
                id: "post-mitigation-traffic",
                component: "LiveTrafficChart",
                props: {
                  title: "Post-Mitigation Traffic Monitor",
                  description: "Real-time traffic returning to baseline — threats should drop to zero",
                  mitigatedIps: ips
                },
                mountedAt: Date.now()
              },
              {
                id: "blocked-threats-summary",
                component: "DynamicDashboard",
                props: {
                  title: "Blocked Threats Summary",
                  description: "Mitigation action results for case INV-412",
                  layoutType: "cards",
                  data: [
                    { label: "Blocked IPs", value: String(ips.length), trend: "stable" },
                    { label: "Strategy", value: strategy.toUpperCase(), trend: "normal" },
                    { label: "Status", value: "Neutralized", trend: "stable" },
                    { label: "Case ID", value: "INV-412", trend: "normal" }
                  ]
                },
                mountedAt: Date.now()
              },
              {
                id: "topology-post-mitigation",
                component: "ThreatTopology",
                props: {
                  title: "Network Topology — Post-Mitigation",
                  nodes: [
                    { id: "45.33.12.99", type: "attacker", label: "45.33.12.99 (BLOCKED)", severity: "low" },
                    { id: "192.168.1.10", type: "clean", label: "192.168.1.10 (Recovered)", severity: "low" },
                    { id: "192.168.1.1", type: "clean", label: "Gateway", severity: "low" }
                  ],
                  edges: [
                    { source: "45.33.12.99", target: "192.168.1.10", attackType: "Blocked", bandwidth: 0 }
                  ]
                },
                mountedAt: Date.now()
              }
            ]
          }

          set({
            messages: [...get().messages, confirmMsg],
            activeWorkspace: postMitigationWorkspace,
            mountedWidgets: postMitigationWorkspace.layout
          })
        }, 1500)
      }
      else if (action === 'clear_memory') {
        proactiveTriggered = false
        mitigationTime = null
        set({
          messages: [],
          mountedWidgets: [],
          activeWorkspace: null,
          blockedIps: new Set<string>(),
          isSimulating: false,
          telemetryBuffer: []
        })
      }
    },

    dismissWidget: (widgetId: string) => {
      const { mountedWidgets, socket, isMockMode } = get()
      set({ mountedWidgets: mountedWidgets.filter(w => w.id !== widgetId) })

      if (!isMockMode && socket && socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({
          type: 'action',
          payload: { action: 'dismiss_widget', id: widgetId },
        }))
      }
    },

    clearMessages: () => {
      const { socket, isMockMode } = get()
      proactiveTriggered = false
      mitigationTime = null
      set({ messages: [], mountedWidgets: [], activeWorkspace: null, blockedIps: new Set<string>(), isSimulating: false, telemetryBuffer: [] })
      
      if (!isMockMode && socket && socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({
          type: 'action',
          payload: { action: 'clear_memory' }
        }))
      }
    },

    triggerDemoStage: (stage: string) => {
      const state = get()
      
      // Auto-fallback and initialize simulator loop if not already running
      if (!state.isMockMode) {
        set({ isMockMode: true, isConnected: true })
        startMockTelemetryLoop()
      }

      switch (stage) {
        case 'attack': {
          set({
            isSimulating: true,
            blockedIps: new Set(),
            telemetryBuffer: []
          })
          proactiveTriggered = true
          mitigationTime = null
          
          const currentWorkspace: InvestigationWorkspace = {
            id: "INV-412",
            title: "Ransomware Lateral Movement Case",
            threatType: "Ransomware",
            confidence: 98.0,
            hypothesis: "Compromised external endpoint (45.33.12.99) is pushing SMB lateral movement anomalies to encrypt network files.",
            evidence: [
              "Unusually high bytes transfer (65,535 bytes) on SMB port 445.",
              "Repeated connections from high-risk external subnet.",
              "Java high-speed packet ingestion classified: threat score = 0.985."
            ],
            layout: [
              {
                id: "traffic-ransomware",
                component: "LiveTrafficChart",
                props: {
                  title: "Active Traffic Spike (Port 445)",
                  description: "Spike detected in Java ingestion packet logs"
                },
                mountedAt: Date.now()
              },
              {
                id: "topology-ransomware",
                component: "ThreatTopology",
                props: {
                  title: "Ransomware Blast Radius",
                  nodes: [
                    { id: "45.33.12.99", type: "attacker", label: "45.33.12.99 (Attacker)", severity: "critical" },
                    { id: "192.168.1.10", type: "victim", label: "192.168.1.10 (Compromised)", severity: "high" },
                    { id: "192.168.1.1", type: "clean", label: "Gateway", severity: "low" }
                  ],
                  edges: [
                    { source: "45.33.12.99", target: "192.168.1.10", attackType: "Ransomware", bandwidth: 65535 }
                  ]
                },
                mountedAt: Date.now()
              },
              {
                id: "mitigate-ransomware",
                component: "MitigationAction",
                props: {
                  title: "Containment Controls",
                  description: "Select isolation scope and execute block rules",
                  threatIps: ["45.33.12.99"],
                  attackType: "Ransomware",
                  severity: "critical",
                  blockDurationHours: 48,
                  scope: "global"
                },
                mountedAt: Date.now()
              }
            ]
          }

          const alertMsg: ChatMessage = {
            id: generateId(),
            type: 'chat',
            role: 'agent',
            content: "⚠️ **CRITICAL THREAT INTRUSION DETECTED**\n\nHigh-volume SMB anomalies detected. I have proactively instantiated investigation workspace **INV-412** and mounted the Threat Topology, Traffic Monitor, and Containment panels. Recommended action: Isolate host immediately.",
            timestamp: Date.now(),
            widgets: currentWorkspace.layout
          }

          set({
            activeWorkspace: currentWorkspace,
            mountedWidgets: currentWorkspace.layout,
            messages: [
              ...state.messages, 
              { id: generateId(), type: 'chat', role: 'user', content: 'Simulate threat intrusion', timestamp: Date.now() }, 
              alertMsg
            ]
          })
          break
        }
        case 'triage': {
          const triageWidget = {
            id: `triage-${Math.floor(Math.random() * 9000) + 1000}`,
            component: "IncidentTriageBoard",
            props: {
              title: "Incident Triage Board",
              description: "Active anomalies requiring operator attention"
            },
            mountedAt: Date.now()
          }

          set({
            activeWorkspace: null,
            mountedWidgets: [triageWidget],
            messages: [
              ...state.messages,
              { id: generateId(), type: 'chat', role: 'user', content: 'Open incident triage board', timestamp: Date.now() },
              { id: generateId(), type: 'chat', role: 'agent', content: '📋 Fetching the current incident triage board.', timestamp: Date.now(), widgets: [triageWidget] }
            ]
          })
          break
        }
        case 'comparison': {
          const active = state.activeWorkspace || {
            id: "INV-412",
            title: "Ransomware Lateral Movement Case",
            threatType: "Ransomware",
            confidence: 98.0,
            hypothesis: "Compromised external endpoint (45.33.12.99) is pushing SMB lateral movement anomalies.",
            evidence: ["Unusually high bytes transfer (65,535 bytes) on SMB port 445."],
            layout: []
          }

          const compWidget = {
            id: "comparison-widget",
            component: "DynamicDashboard",
            props: {
              title: "Historical Baseline Comparison",
              description: "Port 445 SMB comparison against yesterday's normal metrics",
              layoutType: "cards",
              data: [
                { label: "Baseline Traffic", value: "12.4 KB/s", trend: "stable" },
                { label: "Peak Ingress", value: "98.2 MB/s", trend: "critical" }
              ]
            },
            mountedAt: Date.now()
          }

          const baseWidgets = active.layout.filter(w => w.id !== 'comparison-widget')
          const newLayout = [...baseWidgets, compWidget]

          set({
            activeWorkspace: { ...active, layout: newLayout },
            mountedWidgets: newLayout,
            messages: [
              ...state.messages,
              { id: generateId(), type: 'chat', role: 'user', content: 'Compare baseline metrics', timestamp: Date.now() },
              { id: generateId(), type: 'chat', role: 'agent', content: "📊 **Analyzing historical baselines...** I have appended the **Historical Comparison** panel to your active workspace layout.", timestamp: Date.now() }
            ]
          })
          break
        }
        case 'block': {
          // Trigger block action directly
          state.sendAction({
            action: 'isolate_ip',
            ips: ['45.33.12.99'],
            strategy: 'block'
          })
          break
        }
        case 'false_positive': {
          const revisedWorkspace: InvestigationWorkspace = {
            id: "INV-412",
            title: "Investigation Closed: Legitimate Admin Session (False Positive)",
            threatType: "False Positive",
            confidence: 0.0,
            hypothesis: "Initial SMB lateral movement alert was triggered by authorized admin task running backups.",
            evidence: [
              "Authorized administrative credentials (domain_admin_alex) used.",
              "Process parent hash verified against deployment baseline.",
              "Threat neutralized: classified as Legitimate Activity."
            ],
            layout: [
              {
                id: "traffic-ransomware",
                component: "LiveTrafficChart",
                props: {
                  title: "Post-Mitigation Stable Traffic",
                  description: "Port 445 SMB bandwidth check",
                  mitigatedIps: Array.from(state.blockedIps)
                },
                mountedAt: Date.now()
              },
              {
                id: "auth-timeline",
                component: "DynamicDashboard",
                props: {
                  title: "Active Authentication Logs",
                  description: "Verification history of domain_admin_alex credentials",
                  layoutType: "table",
                  columns: [
                    { key: "timestamp", label: "Timestamp" },
                    { key: "user", label: "User Principle" },
                    { key: "action", label: "Action Executed" },
                    { key: "status", label: "Auth Status" }
                  ],
                  rows: [
                    { timestamp: "15:38:12", user: "domain_admin_alex", action: "Kerberos Ticket Grant", status: "Granted" },
                    { timestamp: "15:39:05", user: "domain_admin_alex", action: "Remote Directory Sync", status: "Authorized" }
                  ]
                },
                mountedAt: Date.now()
              },
              {
                id: "security-baselines",
                component: "DynamicDashboard",
                props: {
                  title: "Security Integrity Verification",
                  description: "Host configuration baselines",
                  layoutType: "cards",
                  data: [
                    { label: "Host Integrity", value: "100%", trend: "stable" },
                    { label: "Credential Status", value: "Valid Token", trend: "normal" }
                  ]
                },
                mountedAt: Date.now()
              }
            ]
          }
          set({
            activeWorkspace: revisedWorkspace,
            mountedWidgets: revisedWorkspace.layout,
            messages: [
              ...state.messages,
              { id: generateId(), type: 'chat', role: 'user', content: 'Is this a false positive?', timestamp: Date.now() },
              { id: generateId(), type: 'chat', role: 'agent', content: "🕵️ **Hypothesis Revised & Resolved**\n\nUpon reviewing credential authorization hashes, I have verified that the SMB packets originated from `domain_admin_alex` during a scheduled backup synchronization.\n\nI have marked Case **INV-412** as a **False Positive (Legitimate Activity)** in local memory. I've re-composed the active workspace layout to replace security topology containment tools with the Authentication Verification timeline and Host Integrity panels.", timestamp: Date.now() }
            ]
          })
          break
        }
        case 'report': {
          const active = state.activeWorkspace || {
            id: "INV-412",
            title: "Ransomware Lateral Movement Case",
            threatType: "Ransomware",
            confidence: 98.0,
            hypothesis: "Compromised external endpoint (45.33.12.99) is pushing SMB lateral movement anomalies.",
            evidence: ["Unusually high bytes transfer (65,535 bytes) on SMB port 445."],
            layout: []
          }

          const repWidget = {
            id: "report-widget",
            component: "DynamicDashboard",
            props: {
              title: "Executive Incident Report",
              description: "Auto-generated analysis for incident INV-412",
              layoutType: "document",
              blocks: [
                { type: "title", content: "INCIDENT SUMMARY REPORT: INV-412" },
                { type: "section", content: "1. Incident Overview" },
                { type: "paragraph", content: "At 15:39 UTC, high-speed Java parsing logs flagged anomalous lateral movement traffic originating from high-risk external node 45.33.12.99. Target destination: Internal Server 192.168.1.10." },
                { type: "section", content: "2. Mitigation & Remediation Actions" },
                { type: "paragraph", content: "Operator executed immediate global isolation on the source endpoint. Outbound connections blocked. Post-mitigation metrics verified normal network levels." }
              ]
            },
            mountedAt: Date.now()
          }

          const baseWidgets = active.layout.filter(w => w.id !== 'report-widget')
          const newLayout = [...baseWidgets, repWidget]

          set({
            activeWorkspace: { ...active, layout: newLayout },
            mountedWidgets: newLayout,
            messages: [
              ...state.messages,
              { id: generateId(), type: 'chat', role: 'user', content: 'Generate report for INV-412', timestamp: Date.now() },
              { id: generateId(), type: 'chat', role: 'agent', content: "📝 **Compiling data logs...** I have generated the **Executive Incident Report** document widget and aligned it to your workspace grid.", timestamp: Date.now() }
            ]
          })
          break
        }
      }
    },
  }
})

function anyKeyword(text: string, list: string[]): boolean {
  return list.some(k => text.indexOf(k) !== -1)
}
