/**
 * Q-Guardian OS — Widget Renderer (Component Registry Mapper)
 *
 * Receives a WidgetDescriptor and dynamically renders the matching
 * React component from the registry. Wraps each widget in a
 * glassmorphic card with title bar and controls.
 */

import type { WidgetDescriptor } from '../store/useWebSocketStore'
import { useWebSocketStore } from '../store/useWebSocketStore'
import LiveTrafficChart from './widgets/LiveTrafficChart'
import ThreatTopology from './widgets/ThreatTopology'
import MitigationAction from './widgets/MitigationAction'
import IncidentTriageBoard from './widgets/IncidentTriageBoard'
import DynamicDashboard from './widgets/DynamicDashboard'
import { X, Minimize2, Maximize2, Activity, Network, ShieldAlert, AlertCircle, LayoutDashboard } from 'lucide-react'
import { useState } from 'react'
import { motion } from 'framer-motion'

// ── Component Registry ───────────────────────────────────────────

const WIDGET_REGISTRY: Record<string, React.ComponentType<{ props: Record<string, unknown> }>> = {
  LiveTrafficChart,
  ThreatTopology,
  MitigationAction,
  IncidentTriageBoard,
  DynamicDashboard,
}

const WIDGET_ICONS: Record<string, React.ReactNode> = {
  LiveTrafficChart: <Activity className="w-3.5 h-3.5" />,
  ThreatTopology: <Network className="w-3.5 h-3.5" />,
  MitigationAction: <ShieldAlert className="w-3.5 h-3.5" />,
  IncidentTriageBoard: <AlertCircle className="w-3.5 h-3.5" />,
  DynamicDashboard: <LayoutDashboard className="w-3.5 h-3.5" />,
}

const WIDGET_COLORS: Record<string, string> = {
  LiveTrafficChart: 'from-cyan/20 to-blue/10 border-cyan/25',
  ThreatTopology: 'from-purple/20 to-blue/10 border-purple/25',
  MitigationAction: 'from-threat/20 to-amber/10 border-threat/25',
  IncidentTriageBoard: 'from-deep/80 to-abyss border-border-glow',
  DynamicDashboard: 'from-cyan/10 to-purple/5 border-cyan/20',
}

// ── Renderer ─────────────────────────────────────────────────────

export default function WidgetRenderer({ descriptor }: { descriptor: WidgetDescriptor }) {
  const dismissWidget = useWebSocketStore(s => s.dismissWidget)
  const [minimized, setMinimized] = useState(false)

  const Component = WIDGET_REGISTRY[descriptor.component]
  const icon = WIDGET_ICONS[descriptor.component]
  const colorClass = WIDGET_COLORS[descriptor.component] || 'from-surface/80 to-deep/60 border-border'
  const title = (descriptor.props.title as string) || descriptor.component
  const description = descriptor.props.description as string | undefined

  if (!Component) {
    return (
      <div className="glass-card p-4 border-amber/30">
        <p className="text-sm text-amber">
          ⚠️ Unknown widget: <code className="font-mono text-xs">{descriptor.component}</code>
        </p>
      </div>
    )
  }

  return (
    <motion.div 
      initial={{ opacity: 0, y: 15, scale: 0.95 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      exit={{ opacity: 0, scale: 0.95 }}
      transition={{ type: 'spring', stiffness: 350, damping: 25 }}
      className={`rounded-2xl border bg-gradient-to-br ${colorClass} overflow-hidden shadow-lg`}
    >
      {/* Title Bar */}
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-white/5">
        <div className="flex items-center gap-2.5">
          <div className="w-6 h-6 rounded-lg bg-white/5 flex items-center justify-center text-cyan">
            {icon}
          </div>
          <div>
            <h4 className="text-xs font-semibold text-text leading-none">{title}</h4>
            {description && (
              <p className="text-[10px] text-text-dim mt-0.5">{description}</p>
            )}
          </div>
        </div>
        <div className="flex items-center gap-1">
          <button
            onClick={() => setMinimized(!minimized)}
            className="w-6 h-6 rounded-md hover:bg-white/5 flex items-center justify-center text-text-dim hover:text-text transition-colors cursor-pointer"
            title={minimized ? 'Expand' : 'Minimize'}
          >
            {minimized ? <Maximize2 className="w-3 h-3" /> : <Minimize2 className="w-3 h-3" />}
          </button>
          <button
            onClick={() => dismissWidget(descriptor.id)}
            className="w-6 h-6 rounded-md hover:bg-threat/10 flex items-center justify-center text-text-dim hover:text-threat transition-colors cursor-pointer"
            title="Close widget"
          >
            <X className="w-3 h-3" />
          </button>
        </div>
      </div>

      {/* Widget Content */}
      <motion.div
        initial={false}
        animate={{ height: minimized ? 0 : 'auto', opacity: minimized ? 0 : 1 }}
        transition={{ duration: 0.3, ease: 'easeInOut' }}
        className="overflow-hidden"
      >
        <div className="p-4">
          <Component props={descriptor.props} />
        </div>
      </motion.div>
    </motion.div>
  )
}
