import { useWebSocketStore } from '../store/useWebSocketStore'
import { Shield, Wifi, WifiOff, Activity, Trash2, ShieldAlert, Ban } from 'lucide-react'

export default function Sidebar() {
  const isConnected = useWebSocketStore(s => s.isConnected)
  const widgetCount = useWebSocketStore(s => s.mountedWidgets.length)
  const telemetryCount = useWebSocketStore(s => s.telemetryBuffer.length)
  const clearMessages = useWebSocketStore(s => s.clearMessages)
  const sendMessage = useWebSocketStore(s => s.sendMessage)
  const sendAction = useWebSocketStore(s => s.sendAction)
  const isSimulating = useWebSocketStore(s => s.isSimulating)

  const threatCount = useWebSocketStore(
    s => s.telemetryBuffer.filter(e => e.is_threat).length
  )

  const blockedCount = useWebSocketStore(s => s.blockedIps.size)

  const isMockMode = useWebSocketStore(s => s.isMockMode)

  const toggleSimulation = () => {
    const next = !isSimulating
    useWebSocketStore.setState({ isSimulating: next })
    sendAction({ action: next ? 'simulate_attack' : 'stop_simulation' })
  }

  return (
    <aside className="w-64 shrink-0 bg-abyss border-r border-border flex flex-col">
      {/* Brand */}
      <div className="p-5 border-b border-border">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan to-blue flex items-center justify-center shadow-lg shadow-cyan/20">
            <Shield className="w-5 h-5 text-void" strokeWidth={2.5} />
          </div>
          <div>
            <h1 className="text-base font-bold text-text tracking-tight">Q-Guardian</h1>
            <p className="text-xs font-medium text-cyan tracking-widest uppercase">OS</p>
          </div>
        </div>
      </div>

      {/* Status */}
      <div className="p-4 space-y-3">
        <div className="glass-card p-3">
          <div className="flex items-center gap-2 mb-2">
            <div className={`status-dot ${isMockMode ? 'connected' : isConnected ? 'connected' : 'disconnected'}`} />
            <span className="text-xs font-medium text-text-muted">
              {isMockMode ? 'Sandbox Mode' : isConnected ? 'Connected' : 'Reconnecting...'}
            </span>
          </div>
          <div className="flex items-center gap-2">
            {isMockMode || isConnected
              ? <Wifi className="w-3.5 h-3.5 text-green" />
              : <WifiOff className="w-3.5 h-3.5 text-red" />
            }
            <span className="text-xs text-text-dim font-mono">
              {isMockMode ? 'client-side sandbox' : 'ws://localhost:8000'}
            </span>
          </div>
        </div>

        {/* Metrics */}
        <div className="glass-card p-3 space-y-2">
          <h3 className="text-[10px] uppercase tracking-widest text-text-dim font-semibold">
            Session Metrics
          </h3>
          <div className="grid grid-cols-2 gap-2">
            <MetricPill label="Widgets" value={widgetCount} color="text-cyan" />
            <MetricPill label="Threats" value={threatCount} color="text-threat" />
            <MetricPill label="Events" value={telemetryCount} color="text-amber" />
            <MetricPill label="Blocked" value={blockedCount} color="text-green" />
            <MetricPill
              label="Score"
              value={telemetryCount > 0
                ? `${Math.round((threatCount / telemetryCount) * 100)}%`
                : '—'
              }
              color="text-purple"
            />
          </div>
        </div>

        {/* Simulation Node */}
        <div className="glass-card p-3 space-y-2">
          <h3 className="text-[10px] uppercase tracking-widest text-text-dim font-semibold">
            Simulation Control
          </h3>
          <button
            onClick={toggleSimulation}
            disabled={!isConnected}
            className={`w-full flex items-center justify-center gap-2 px-3 py-2 rounded-lg text-xs font-semibold tracking-wide transition-all duration-200 cursor-pointer border ${
              isSimulating
                ? 'bg-threat/20 border-threat/40 text-threat hover:bg-threat/30 animate-pulse'
                : 'bg-cyan/10 border-cyan/20 text-cyan hover:bg-cyan/15 hover:border-cyan/35'
            } disabled:opacity-40 disabled:cursor-not-allowed`}
          >
            {isSimulating ? '🛑 Stop Simulation' : '⚡ Simulate Attack'}
          </button>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="p-4 space-y-2 mt-auto border-t border-border">
        <h3 className="text-[10px] uppercase tracking-widest text-text-dim font-semibold mb-2">
          Quick Actions
        </h3>
        <QuickBtn
          icon={<Activity className="w-3.5 h-3.5" />}
          label="Live Traffic"
          onClick={() => sendMessage('Show me live network traffic')}
          disabled={!isConnected}
        />
        <QuickBtn
          icon={<Shield className="w-3.5 h-3.5" />}
          label="Threat Topology"
          onClick={() => sendMessage('Analyze the threat topology')}
          disabled={!isConnected}
        />
        <QuickBtn
          icon={<Trash2 className="w-3.5 h-3.5" />}
          label="Clear Chat"
          onClick={clearMessages}
          variant="muted"
        />
      </div>
    </aside>
  )
}

function MetricPill({ label, value, color }: { label: string; value: string | number; color: string }) {
  return (
    <div className="bg-deep/60 rounded-lg px-2.5 py-1.5 text-center">
      <div className={`text-sm font-bold font-mono ${color}`}>{value}</div>
      <div className="text-[9px] text-text-dim uppercase tracking-wider">{label}</div>
    </div>
  )
}

function QuickBtn({
  icon,
  label,
  onClick,
  disabled,
  variant = 'default',
}: {
  icon: React.ReactNode
  label: string
  onClick: () => void
  disabled?: boolean
  variant?: 'default' | 'muted'
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`
        w-full flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium
        transition-all duration-200 cursor-pointer
        ${variant === 'muted'
          ? 'text-text-dim hover:text-text-muted hover:bg-elevated/50'
          : 'text-text-muted hover:text-cyan hover:bg-cyan/5 hover:border-cyan/20'
        }
        border border-transparent
        disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-transparent
      `}
    >
      {icon}
      {label}
    </button>
  )
}
