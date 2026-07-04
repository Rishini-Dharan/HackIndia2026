import { useState } from 'react'
import { useWebSocketStore } from '../store/useWebSocketStore'
import { Shield, Wifi, WifiOff, Activity, Trash2, ShieldAlert, Ban, Layers, Search, FileText } from 'lucide-react'

export default function Sidebar() {
  const isConnected = useWebSocketStore(s => s.isConnected)
  const widgetCount = useWebSocketStore(s => s.mountedWidgets.length)
  const telemetryCount = useWebSocketStore(s => s.telemetryBuffer.length)
  const clearMessages = useWebSocketStore(s => s.clearMessages)
  const sendMessage = useWebSocketStore(s => s.sendMessage)
  const sendAction = useWebSocketStore(s => s.sendAction)
  const isSimulating = useWebSocketStore(s => s.isSimulating)
  const triggerDemoStage = useWebSocketStore(s => s.triggerDemoStage)
  const [activeStep, setActiveStep] = useState<string | null>(null)

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

      {/* Scrollable Sidebar Content Area */}
      <div className="flex-grow overflow-y-auto p-4 space-y-3.5 custom-scrollbar">
        
        {/* Status */}
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

        {/* Jury Walkthrough */}
        <div className="glass-card p-3 border-purple/35 bg-purple/5 space-y-2">
          <div className="flex items-center justify-between">
            <h3 className="text-[10px] uppercase tracking-widest text-purple font-bold">
              Jury Walkthrough
            </h3>
            <span className="text-[9px] bg-purple/20 text-purple px-1.5 py-0.5 rounded font-semibold uppercase">
              Demo Guide
            </span>
          </div>
          <p className="text-[9px] text-text-dim leading-relaxed">
            Morph the interface step-by-step to test the complete dynamic telemetry response.
          </p>
          <div className="space-y-1.5 pt-1">
            <DemoStepBtn
              num="1"
              label="Trigger Attack"
              icon={<ShieldAlert className="w-3.5 h-3.5 text-threat" />}
              active={activeStep === 'attack'}
              onClick={() => {
                setActiveStep('attack')
                triggerDemoStage('attack')
              }}
            />
            <DemoStepBtn
              num="2"
              label="View Triage Board"
              icon={<Layers className="w-3.5 h-3.5 text-amber" />}
              active={activeStep === 'triage'}
              onClick={() => {
                setActiveStep('triage')
                triggerDemoStage('triage')
              }}
            />
            <DemoStepBtn
              num="3"
              label="Check Baselines"
              icon={<Search className="w-3.5 h-3.5 text-cyan" />}
              active={activeStep === 'comparison'}
              onClick={() => {
                setActiveStep('comparison')
                triggerDemoStage('comparison')
              }}
            />
            <DemoStepBtn
              num="4"
              label="Execute IP Isolation"
              icon={<Ban className="w-3.5 h-3.5 text-threat" />}
              active={activeStep === 'block'}
              onClick={() => {
                setActiveStep('block')
                triggerDemoStage('block')
              }}
            />
            <DemoStepBtn
              num="5"
              label="False Positive Check"
              icon={<Shield className="w-3.5 h-3.5 text-green" />}
              active={activeStep === 'false_positive'}
              onClick={() => {
                setActiveStep('false_positive')
                triggerDemoStage('false_positive')
              }}
            />
            <DemoStepBtn
              num="6"
              label="Gen Incident Report"
              icon={<FileText className="w-3.5 h-3.5 text-purple" />}
              active={activeStep === 'report'}
              onClick={() => {
                setActiveStep('report')
                triggerDemoStage('report')
              }}
            />
          </div>
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

function DemoStepBtn({
  num,
  label,
  icon,
  active,
  onClick,
}: {
  num: string
  label: string
  icon: React.ReactNode
  active: boolean
  onClick: () => void
}) {
  return (
    <button
      onClick={onClick}
      className={`
        w-full flex items-center gap-2 px-2.5 py-1.5 rounded-lg text-[10px] font-semibold
        transition-all duration-200 cursor-pointer border text-left
        ${active
          ? 'bg-purple/15 border-purple/40 text-purple shadow-sm shadow-purple/10'
          : 'bg-deep/30 border-white/5 text-text-dim hover:border-purple/20 hover:text-text-muted hover:bg-white/2'
        }
      `}
    >
      <span className={`w-4 h-4 rounded-md flex items-center justify-center text-[9px] font-mono font-bold ${
        active ? 'bg-purple text-void' : 'bg-white/5 text-text-dim'
      }`}>{num}</span>
      <span className="flex-1 truncate">{label}</span>
      <span>{icon}</span>
    </button>
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
