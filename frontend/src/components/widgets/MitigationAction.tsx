/**
 * Q-Guardian OS — Mitigation Action Widget
 *
 * A reactive form allowing the operator to isolate compromised IPs,
 * choose a mitigation strategy, and send the action back up the WebSocket.
 */

import { useState } from 'react'
import { useWebSocketStore } from '../../store/useWebSocketStore'
import { ShieldAlert, Ban, Gauge, Box, CheckCircle2, Loader2 } from 'lucide-react'

type Strategy = 'block' | 'rate-limit' | 'quarantine'

const STRATEGY_META: Record<Strategy, { label: string; icon: React.ReactNode; desc: string; color: string }> = {
  block: {
    label: 'Block',
    icon: <Ban className="w-4 h-4" />,
    desc: 'Immediately drop all traffic from selected IPs.',
    color: 'border-threat/40 bg-threat/5 text-threat',
  },
  'rate-limit': {
    label: 'Rate-Limit',
    icon: <Gauge className="w-4 h-4" />,
    desc: 'Throttle traffic to 10% of normal throughput.',
    color: 'border-amber/40 bg-amber/5 text-amber',
  },
  quarantine: {
    label: 'Quarantine',
    icon: <Box className="w-4 h-4" />,
    desc: 'Redirect traffic to sandbox for analysis.',
    color: 'border-purple/40 bg-purple/5 text-purple',
  },
}

export default function MitigationAction({ props }: { props: Record<string, unknown> }) {
  const threatIps = (props.threatIps as string[]) || []
  const attackType = (props.attackType as string) || 'Unknown'
  const severity = (props.severity as string) || 'high'

  const sendAction = useWebSocketStore(s => s.sendAction)

  const [selectedIps, setSelectedIps] = useState<Set<string>>(new Set(threatIps))
  const [strategy, setStrategy] = useState<Strategy>('block')
  const [duration, setDuration] = useState<number>((props.blockDurationHours as number) || 24)
  const [scope, setScope] = useState<'global' | 'local'>((props.scope as 'global' | 'local') || 'global')
  const [notes, setNotes] = useState('')
  const [status, setStatus] = useState<'idle' | 'executing' | 'done'>('idle')

  const toggleIp = (ip: string) => {
    const next = new Set(selectedIps)
    if (next.has(ip)) next.delete(ip)
    else next.add(ip)
    setSelectedIps(next)
  }

  const selectAll = () => {
    setSelectedIps(new Set(threatIps))
  }

  const handleExecute = () => {
    if (selectedIps.size === 0) return

    setStatus('executing')

    sendAction({
      action: 'isolate_ip',
      ips: Array.from(selectedIps),
      strategy,
      duration,
      scope,
      notes,
      attackType,
    })

    // Simulate execution delay
    setTimeout(() => setStatus('done'), 1500)
  }

  if (status === 'done') {
    return (
      <div className="flex flex-col items-center justify-center py-8 space-y-3">
        <div className="w-14 h-14 rounded-full bg-green/10 border border-green/30 flex items-center justify-center">
          <CheckCircle2 className="w-7 h-7 text-green" />
        </div>
        <h4 className="text-sm font-semibold text-green">Mitigation Executed Successfully</h4>
        <p className="text-xs text-text-muted text-center max-w-xs">
          {selectedIps.size} IP{selectedIps.size !== 1 ? 's' : ''} have been {strategy === 'block' ? 'blocked' : strategy === 'rate-limit' ? 'rate-limited' : 'quarantined'}.
          Firewall rules are now active.
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Severity Banner */}
      <div className={`flex items-center gap-2.5 px-3 py-2 rounded-lg border ${
        severity === 'critical'
          ? 'border-threat/30 bg-threat/5'
          : 'border-amber/30 bg-amber/5'
      }`}>
        <ShieldAlert className={`w-4 h-4 ${severity === 'critical' ? 'text-threat' : 'text-amber'}`} />
        <div>
          <span className={`text-xs font-semibold ${severity === 'critical' ? 'text-threat' : 'text-amber'}`}>
            {severity.toUpperCase()} — {attackType} Attack
          </span>
          <p className="text-[10px] text-text-dim">Immediate response recommended</p>
        </div>
      </div>

      {/* IP Selection */}
      <div>
        <div className="flex items-center justify-between mb-2">
          <label className="text-xs font-semibold text-text-muted">
            Threat IPs ({selectedIps.size}/{threatIps.length} selected)
          </label>
          <button
            onClick={selectAll}
            className="text-[10px] text-cyan hover:text-cyan/80 transition-colors cursor-pointer"
          >
            Select All
          </button>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {threatIps.map(ip => (
            <button
              key={ip}
              onClick={() => toggleIp(ip)}
              className={`
                px-2.5 py-1 rounded-md text-xs font-mono transition-all duration-200 cursor-pointer
                ${selectedIps.has(ip)
                  ? 'bg-threat/15 border border-threat/40 text-threat'
                  : 'bg-deep border border-border text-text-dim hover:border-border-glow hover:text-text-muted'
                }
              `}
            >
              {ip}
            </button>
          ))}
        </div>
      </div>

      {/* Strategy Selection */}
      <div>
        <label className="text-xs font-semibold text-text-muted block mb-2">
          Mitigation Strategy
        </label>
        <div className="grid grid-cols-3 gap-2">
          {(Object.keys(STRATEGY_META) as Strategy[]).map(s => {
            const meta = STRATEGY_META[s]
            const active = strategy === s
            return (
              <button
                key={s}
                onClick={() => setStrategy(s)}
                className={`
                  flex flex-col items-center gap-1.5 px-3 py-2.5 rounded-lg border text-xs
                  transition-all duration-200 cursor-pointer
                  ${active
                    ? meta.color
                    : 'border-border bg-deep/50 text-text-dim hover:border-border-glow'
                  }
                `}
              >
                {meta.icon}
                <span className="font-semibold">{meta.label}</span>
              </button>
            )
          })}
        </div>
        <p className="text-[10px] text-text-dim mt-1.5">{STRATEGY_META[strategy].desc}</p>
      </div>

      <div className="grid grid-cols-2 gap-4">
        {/* Block Duration Slider */}
        <div>
          <label className="text-xs font-semibold text-text-muted flex justify-between mb-2">
            <span>Duration (Hours)</span>
            <span className="text-cyan font-mono">{duration}h</span>
          </label>
          <input
            type="range"
            min="1"
            max="72"
            value={duration}
            onChange={(e) => setDuration(parseInt(e.target.value))}
            className="w-full h-1.5 bg-deep rounded-lg appearance-none cursor-pointer accent-cyan"
          />
        </div>

        {/* Network Scope Toggle */}
        <div>
          <label className="text-xs font-semibold text-text-muted block mb-2">
            Network Scope
          </label>
          <div className="flex bg-deep rounded-lg p-1">
            <button
              onClick={() => setScope('global')}
              className={`flex-1 py-1 text-xs font-medium rounded-md transition-all ${
                scope === 'global' ? 'bg-cyan/20 text-cyan shadow-sm' : 'text-text-dim hover:text-text'
              }`}
            >
              Global
            </button>
            <button
              onClick={() => setScope('local')}
              className={`flex-1 py-1 text-xs font-medium rounded-md transition-all ${
                scope === 'local' ? 'bg-cyan/20 text-cyan shadow-sm' : 'text-text-dim hover:text-text'
              }`}
            >
              Local Only
            </button>
          </div>
        </div>
      </div>

      {/* Notes */}
      <div>
        <label className="text-xs font-semibold text-text-muted block mb-1.5">
          Notes (optional)
        </label>
        <textarea
          value={notes}
          onChange={e => setNotes(e.target.value)}
          placeholder="Add context for the incident report..."
          rows={2}
          className="
            w-full px-3 py-2 rounded-lg text-xs font-sans
            bg-deep border border-border text-text placeholder:text-text-dim
            focus:outline-none focus:border-cyan/40 focus:ring-1 focus:ring-cyan/20
            transition-all duration-200 resize-none
          "
        />
      </div>

      {/* Execute Button */}
      <button
        onClick={handleExecute}
        disabled={selectedIps.size === 0 || status === 'executing'}
        className={`
          w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold
          transition-all duration-200 cursor-pointer
          ${status === 'executing'
            ? 'bg-amber/20 border border-amber/30 text-amber cursor-wait'
            : 'bg-gradient-to-r from-threat/80 to-amber/60 text-void hover:shadow-lg hover:shadow-threat/20 active:scale-[0.98]'
          }
          disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:shadow-none
        `}
      >
        {status === 'executing' ? (
          <>
            <Loader2 className="w-4 h-4 animate-spin" />
            Applying Firewall Rules...
          </>
        ) : (
          <>
            <ShieldAlert className="w-4 h-4" />
            Execute Mitigation ({selectedIps.size} IP{selectedIps.size !== 1 ? 's' : ''})
          </>
        )}
      </button>
    </div>
  )
}
