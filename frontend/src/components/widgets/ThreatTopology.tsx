/**
 * Q-Guardian OS — Threat Topology Widget
 *
 * A visual SVG node-link diagram showing the attack blast radius.
 * Nodes: attacker (red pulsing), victim (amber), clean (green).
 * Edges: animated dashed lines showing traffic flow.
 */

import { useMemo, useState } from 'react'
import { AlertTriangle, Server, Shield, ShieldAlert, Search, X, Layers } from 'lucide-react'
import { useWebSocketStore } from '../../store/useWebSocketStore'

interface TopoNode {
  id: string
  type: 'attacker' | 'victim' | 'clean'
  label: string
  severity: string
}

interface TopoEdge {
  source: string
  target: string
  attackType: string
  bandwidth: number
}

interface TooltipState {
  x: number
  y: number
  node: TopoNode | null
}

const NODE_COLORS: Record<string, { fill: string; stroke: string; glow: string }> = {
  attacker: { fill: '#ff3e3e', stroke: '#ff6b6b', glow: 'rgba(255,62,62,0.4)' },
  victim: { fill: '#f59e0b', stroke: '#fbbf24', glow: 'rgba(245,158,11,0.3)' },
  clean: { fill: '#22c55e', stroke: '#4ade80', glow: 'rgba(34,197,94,0.3)' },
}

const NODE_RADIUS: Record<string, number> = {
  attacker: 22,
  victim: 16,
  clean: 12,
}

export default function ThreatTopology({ props }: { props: Record<string, unknown> }) {
  const nodes = (props.nodes as TopoNode[]) || []
  const edges = (props.edges as TopoEdge[]) || []
  const [tooltip, setTooltip] = useState<TooltipState>({ x: 0, y: 0, node: null })
  const [contextMenu, setContextMenu] = useState<{ x: number, y: number, node: TopoNode & { isBlocked?: boolean } } | null>(null)
  const sendAction = useWebSocketStore(s => s.sendAction)
  const blockedIps = useWebSocketStore(s => s.blockedIps)

  const dynamicNodes = useMemo(() => {
    return nodes.map(n => {
      if (blockedIps.has(n.id)) {
        return {
          ...n,
          type: 'clean' as const,
          label: `${n.id} (Blocked)`,
          severity: 'low',
          isBlocked: true
        }
      }
      return { ...n, isBlocked: false }
    })
  }, [nodes, blockedIps])

  const dynamicEdges = useMemo(() => {
    return edges.map(e => {
      if (blockedIps.has(e.source) || blockedIps.has(e.target)) {
        return {
          ...e,
          bandwidth: 0,
          attackType: 'Blocked'
        }
      }
      return e
    })
  }, [edges, blockedIps])

  // Layout: position nodes in a force-like radial arrangement
  const positions = useMemo(() => {
    const pos: Record<string, { x: number; y: number }> = {}
    const width = 600
    const height = 320
    const cx = width / 2
    const cy = height / 2

    const attackers = nodes.filter(n => n.type === 'attacker')
    const victims = nodes.filter(n => n.type === 'victim')
    const clean = nodes.filter(n => n.type === 'clean')

    // Attackers on the left
    attackers.forEach((n, i) => {
      const angle = ((i - (attackers.length - 1) / 2) * 0.5) - Math.PI * 0.8
      pos[n.id] = {
        x: cx + Math.cos(angle) * 180,
        y: cy + Math.sin(angle) * 100,
      }
    })

    // Victims in the center-right
    victims.forEach((n, i) => {
      const angle = ((i - (victims.length - 1) / 2) * 0.4)
      pos[n.id] = {
        x: cx + 40 + Math.cos(angle) * 60,
        y: cy + Math.sin(angle) * 90,
      }
    })

    // Clean hosts on the right
    clean.forEach((n, i) => {
      const angle = ((i - (clean.length - 1) / 2) * 0.5) + Math.PI * 0.15
      pos[n.id] = {
        x: cx + Math.cos(angle) * 220,
        y: cy + Math.sin(angle) * 110,
      }
    })

    return pos
  }, [nodes])

  if (nodes.length === 0) {
    return (
      <div className="h-40 flex items-center justify-center text-text-dim text-xs">
        No topology data available
      </div>
    )
  }

  return (
    <div className="space-y-3">
      {/* Legend */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4 text-[10px] text-text-muted">
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-threat" /> Attacker ({dynamicNodes.filter(n => n.type === 'attacker').length})
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-amber" /> Victim ({dynamicNodes.filter(n => n.type === 'victim').length})
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-green" /> Clean/Blocked ({dynamicNodes.filter(n => n.type === 'clean').length})
          </span>
        </div>
        <span className="text-[10px] text-text-dim font-mono">
          {dynamicEdges.length} vector{dynamicEdges.length !== 1 ? 's' : ''}
        </span>
      </div>

      {/* SVG Topology */}
      <div className="relative rounded-xl bg-black/20 border border-white/5 overflow-hidden">
        <svg
          viewBox="0 0 600 320"
          className="w-full h-auto"
          style={{ minHeight: '260px' }}
        >
          <defs>
            {/* Glow filters */}
            <filter id="glow-red" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur stdDeviation="4" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
            <filter id="glow-amber" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          {/* Edges */}
          {dynamicEdges.map((edge, i) => {
            const from = positions[edge.source]
            const to = positions[edge.target]
            if (!from || !to) return null

            const isBlocked = edge.bandwidth === 0
            return (
              <g key={`edge-${i}`}>
                <line
                  x1={from.x}
                  y1={from.y}
                  x2={to.x}
                  y2={to.y}
                  stroke={isBlocked ? "#22c55e" : "#ff3e3e"}
                  strokeWidth={isBlocked ? 1.5 : Math.max(1.5, Math.min(3.5, edge.bandwidth / 15000))}
                  strokeOpacity={0.6}
                  strokeDasharray={isBlocked ? "3, 3" : undefined}
                  className={isBlocked ? "" : "edge-animated"}
                />
                {/* Attack type label at midpoint */}
                <text
                  x={(from.x + to.x) / 2}
                  y={(from.y + to.y) / 2 - 6}
                  fontSize="8"
                  fill={isBlocked ? "#22c55e" : "#f59e0b"}
                  textAnchor="middle"
                  fontFamily="'JetBrains Mono', monospace"
                >
                  {edge.attackType}
                </text>
              </g>
            )
          })}

          {/* Nodes */}
          {dynamicNodes.map((node) => {
            const pos = positions[node.id]
            if (!pos) return null

            const color = NODE_COLORS[node.type]
            const r = NODE_RADIUS[node.type]
            const filterAttr = node.type === 'attacker' ? 'url(#glow-red)'
              : node.type === 'victim' ? 'url(#glow-amber)' : undefined

            return (
              <g
                key={node.id}
                onMouseEnter={() => {
                  if (!contextMenu) setTooltip({ x: pos.x, y: pos.y, node })
                }}
                onMouseLeave={() => setTooltip({ x: 0, y: 0, node: null })}
                onClick={() => {
                  setTooltip({ x: 0, y: 0, node: null })
                  setContextMenu({ x: pos.x, y: pos.y, node })
                }}
                className={`cursor-pointer ${contextMenu?.node.id === node.id ? 'opacity-100' : contextMenu ? 'opacity-30' : ''} transition-opacity duration-300`}
              >
                {/* Pulse ring for attackers */}
                {node.type === 'attacker' && (
                  <circle
                    cx={pos.x}
                    cy={pos.y}
                    r={r + 6}
                    fill="none"
                    stroke={color.fill}
                    strokeWidth={1.5}
                    strokeOpacity={0.3}
                  >
                    <animate
                      attributeName="r"
                      values={`${r + 4};${r + 12};${r + 4}`}
                      dur="2s"
                      repeatCount="indefinite"
                    />
                    <animate
                      attributeName="stroke-opacity"
                      values="0.4;0.1;0.4"
                      dur="2s"
                      repeatCount="indefinite"
                    />
                  </circle>
                )}

                {/* Main node circle */}
                <circle
                  cx={pos.x}
                  cy={pos.y}
                  r={r}
                  fill={node.isBlocked ? '#22c55e' : color.fill}
                  fillOpacity={0.15}
                  stroke={node.isBlocked ? '#4ade80' : color.stroke}
                  strokeWidth={2}
                  filter={node.isBlocked ? undefined : filterAttr}
                />

                {/* Inner icon */}
                <text
                  x={pos.x}
                  y={pos.y + 4}
                  fontSize="12"
                  fill={node.isBlocked ? '#22c55e' : color.fill}
                  textAnchor="middle"
                >
                  {node.isBlocked ? '🛡️' : node.type === 'attacker' ? '⚡' : node.type === 'victim' ? '🖥' : '✓'}
                </text>

                {/* IP label */}
                <text
                  x={pos.x}
                  y={pos.y + r + 14}
                  fontSize="8"
                  fill={node.isBlocked ? '#4ade80' : '#94a3b8'}
                  textAnchor="middle"
                  fontFamily="'JetBrains Mono', monospace"
                >
                  {node.label}
                </text>
              </g>
            )
          })}
        </svg>

        {/* Tooltip */}
        {tooltip.node && (
          <div
            className="absolute pointer-events-none z-10 glass-card px-3 py-2 text-[11px] shadow-xl"
            style={{
              left: `${(tooltip.x / 600) * 100}%`,
              top: `${(tooltip.y / 320) * 100 - 15}%`,
              transform: 'translate(-50%, -100%)',
            }}
          >
            <div className="flex items-center gap-1.5 mb-1">
              {tooltip.node.type === 'attacker'
                ? <AlertTriangle className="w-3 h-3 text-threat" />
                : tooltip.node.type === 'victim'
                  ? <Server className="w-3 h-3 text-amber" />
                  : <Shield className="w-3 h-3 text-green" />
              }
              <span className="font-semibold text-text">{tooltip.node.label}</span>
            </div>
            <div className="text-text-dim">
              Type: <span className="text-text capitalize">{tooltip.node.type}</span>
              {' · '}
              Severity: <span className="text-text">{tooltip.node.severity}</span>
            </div>
          </div>
        )}

        {/* Context Menu */}
        {contextMenu && (
          <div
            className="absolute z-20 glass-card shadow-2xl border border-white/10 rounded-xl overflow-hidden backdrop-blur-md w-52"
            style={{
              left: `${(contextMenu.x / 600) * 100}%`,
              top: `${(contextMenu.y / 320) * 100}%`,
              transform: 'translate(15px, -15px)',
            }}
          >
            <div className="flex items-center justify-between px-3 py-2 border-b border-white/5 bg-white/5">
              <span className={`text-[11px] font-semibold flex items-center gap-1.5 ${
                contextMenu.node.isBlocked ? 'text-green' :
                contextMenu.node.type === 'attacker' ? 'text-threat' :
                contextMenu.node.type === 'victim' ? 'text-amber' : 'text-cyan'
              }`}>
                {contextMenu.node.isBlocked ? '🛡️' : '🖥'}
                {contextMenu.node.id}
              </span>
              <button
                onClick={() => setContextMenu(null)}
                className="w-5 h-5 rounded hover:bg-white/10 flex items-center justify-center text-text-dim hover:text-text cursor-pointer"
              >
                <X className="w-3 h-3" />
              </button>
            </div>
            <div className="p-1">
              {/* Attacker (Not Blocked) */}
              {contextMenu.node.type === 'attacker' && !contextMenu.node.isBlocked && (
                <>
                  <button
                    onClick={() => {
                      sendAction({ action: 'isolate_ip', ips: [contextMenu.node.id], strategy: 'block' })
                      setContextMenu(null)
                    }}
                    className="w-full flex items-center gap-2 px-2 py-1.5 text-xs text-text hover:bg-threat/10 hover:text-threat rounded-lg transition-colors cursor-pointer text-left font-semibold"
                  >
                    <ShieldAlert className="w-3.5 h-3.5" />
                    Block Attacker IP
                  </button>
                  <button
                    onClick={() => {
                      sendAction({ action: 'chat_command', command: 'Investigate ' + contextMenu.node.id })
                      setContextMenu(null)
                    }}
                    className="w-full flex items-center gap-2 px-2 py-1.5 text-xs text-text hover:bg-white/5 rounded-lg transition-colors cursor-pointer text-left"
                  >
                    <Search className="w-3.5 h-3.5 text-cyan" />
                    Investigate
                  </button>
                </>
              )}

              {/* Attacker (Already Blocked) */}
              {contextMenu.node.isBlocked && (
                <button
                  onClick={() => {
                    sendAction({ action: 'unblock_ip', ips: [contextMenu.node.id] })
                    setContextMenu(null)
                  }}
                  className="w-full flex items-center gap-2 px-2 py-1.5 text-xs text-text hover:bg-green/10 hover:text-green rounded-lg transition-colors cursor-pointer text-left font-semibold"
                >
                  <Shield className="w-3.5 h-3.5 text-green" />
                  Unblock & Restore IP
                </button>
              )}

              {/* Victim Node */}
              {contextMenu.node.type === 'victim' && (
                <>
                  <button
                    onClick={() => {
                      sendAction({ action: 'isolate_ip', ips: [contextMenu.node.id], strategy: 'quarantine' })
                      setContextMenu(null)
                    }}
                    className="w-full flex items-center gap-2 px-2 py-1.5 text-xs text-text hover:bg-amber/10 hover:text-amber rounded-lg transition-colors cursor-pointer text-left"
                  >
                    <ShieldAlert className="w-3.5 h-3.5" />
                    Quarantine Host
                  </button>
                  <button
                    onClick={() => {
                      sendAction({ action: 'chat_command', command: 'Compare baselines' })
                      setContextMenu(null)
                    }}
                    className="w-full flex items-center gap-2 px-2 py-1.5 text-xs text-text hover:bg-white/5 rounded-lg transition-colors cursor-pointer text-left"
                  >
                    <Layers className="w-3.5 h-3.5 text-cyan" />
                    Analyze Baselines
                  </button>
                </>
              )}

              {/* Clean/Healthy Nodes */}
              {contextMenu.node.type === 'clean' && !contextMenu.node.isBlocked && (
                <button
                  onClick={() => {
                    sendAction({ action: 'chat_command', command: 'Compare baselines' })
                    setContextMenu(null)
                  }}
                  className="w-full flex items-center gap-2 px-2 py-1.5 text-xs text-text hover:bg-white/5 rounded-lg transition-colors cursor-pointer text-left"
                >
                  <Layers className="w-3.5 h-3.5 text-cyan" />
                  Check Auth Logs
                </button>
              )}

              <button
                onClick={() => {
                  sendAction({ action: 'chat_command', command: 'triage' })
                  setContextMenu(null)
                }}
                className="w-full flex items-center gap-2 px-2 py-1.5 text-xs text-text hover:bg-white/5 border-t border-white/5 mt-1 rounded-lg transition-colors cursor-pointer text-left text-text-muted"
              >
                <Layers className="w-3.5 h-3.5 text-purple" />
                View Incident Board
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Attack Vectors Table */}
      {dynamicEdges.length > 0 && (
        <div className="rounded-lg bg-black/20 border border-white/5 overflow-hidden">
          <table className="w-full text-[11px]">
            <thead>
              <tr className="border-b border-white/5">
                <th className="text-left px-3 py-1.5 text-text-dim font-medium">Source</th>
                <th className="text-left px-3 py-1.5 text-text-dim font-medium">Target</th>
                <th className="text-left px-3 py-1.5 text-text-dim font-medium">Attack</th>
                <th className="text-right px-3 py-1.5 text-text-dim font-medium">Bandwidth</th>
              </tr>
            </thead>
            <tbody>
              {dynamicEdges.map((edge, i) => {
                const isBlocked = edge.bandwidth === 0
                return (
                  <tr key={i} className="border-b border-white/3 last:border-b-0 hover:bg-white/2">
                    <td className={`px-3 py-1.5 font-mono ${isBlocked ? 'text-green' : 'text-threat'}`}>{edge.source}</td>
                    <td className="px-3 py-1.5 font-mono text-amber">{edge.target}</td>
                    <td className={`px-3 py-1.5 ${isBlocked ? 'text-green font-medium' : ''}`}>{edge.attackType}</td>
                    <td className={`px-3 py-1.5 text-right font-mono ${isBlocked ? 'text-green' : ''}`}>
                      {isBlocked ? '0 B/s' : `${edge.bandwidth.toLocaleString()} B/s`}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
