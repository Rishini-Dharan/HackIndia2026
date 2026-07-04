/**
 * Q-Guardian OS — Investigation Workspace Banner & Info Panel
 */

import { useWebSocketStore } from '../store/useWebSocketStore'
import { ShieldAlert, AlertTriangle, CheckCircle, Clock } from 'lucide-react'

export default function InvestigationBanner() {
  const activeWorkspace = useWebSocketStore((s) => s.activeWorkspace)
  const isConnected = useWebSocketStore((s) => s.isConnected)
  const clearMessages = useWebSocketStore((s) => s.clearMessages)

  if (!activeWorkspace) return null

  // Check status (if there is a Neutralized fact in message history, set status to neutralized)
  const isNeutralized = activeWorkspace.title.toLowerCase().includes('neutral') || 
    useWebSocketStore.getState().messages.some(m => m.content.includes('neutralized'))

  return (
    <div className="bg-gradient-to-br from-threat/15 to-void border border-threat/25 rounded-2xl p-5 shadow-xl relative overflow-hidden shrink-0">
      {/* Background glow */}
      <div className="absolute top-0 right-0 w-32 h-32 bg-threat/10 rounded-full blur-3xl pointer-events-none" />

      <div className="flex flex-col md:flex-row justify-between gap-4 items-start md:items-center border-b border-white/5 pb-4 mb-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-threat/20 border border-threat/40 flex items-center justify-center text-threat animate-pulse">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-bold font-mono tracking-wider text-threat uppercase bg-threat/10 border border-threat/30 px-2 py-0.5 rounded">
                Active Case: {activeWorkspace.id}
              </span>
              <span className={`text-[10px] font-bold font-mono px-2 py-0.5 rounded flex items-center gap-1 ${
                isNeutralized 
                  ? 'bg-green/10 border border-green/30 text-green' 
                  : 'bg-amber/10 border border-amber/30 text-amber'
              }`}>
                {isNeutralized ? <CheckCircle className="w-3 h-3" /> : <Clock className="w-3 h-3" />}
                {isNeutralized ? 'NEUTRALIZED' : 'UNDER INVESTIGATION'}
              </span>
            </div>
            <h3 className="text-sm font-bold text-text mt-1">{activeWorkspace.title}</h3>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <div className="text-right">
            <span className="text-[10px] text-text-dim uppercase tracking-wider block font-semibold">
              Threat Confidence
            </span>
            <span className="text-lg font-bold font-mono text-threat">
              {activeWorkspace.confidence}%
            </span>
          </div>
          <button
            onClick={clearMessages}
            className="px-3 py-1.5 rounded-lg border border-white/10 hover:border-white/20 text-[10px] font-semibold text-text-muted hover:text-text bg-white/5 transition-all cursor-pointer"
          >
            Dismiss Case
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-5 text-xs">
        {/* Hypothesis */}
        <div className="space-y-1.5">
          <span className="font-bold text-text-muted uppercase tracking-wider text-[10px] flex items-center gap-1.5">
            <AlertTriangle className="w-3.5 h-3.5 text-threat" /> Active Hypothesis
          </span>
          <p className="text-text leading-relaxed font-light bg-black/10 border border-white/5 p-3 rounded-xl italic">
            "{activeWorkspace.hypothesis}"
          </p>
        </div>

        {/* Evidence Logs */}
        <div className="space-y-1.5">
          <span className="font-bold text-text-muted uppercase tracking-wider text-[10px]">
            ⚡ Investigative Evidence Logs
          </span>
          <ul className="space-y-1 pl-1.5 font-sans font-light text-text-muted leading-relaxed">
            {activeWorkspace.evidence.map((ev, idx) => (
              <li key={idx} className="flex items-start gap-2">
                <span className="text-threat mt-1">•</span>
                <span>{ev}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  )
}
