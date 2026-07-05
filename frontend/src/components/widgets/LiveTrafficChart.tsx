/**
 * Q-Guardian OS — Live Traffic Chart Widget
 *
 * A streaming Recharts AreaChart that updates every 500ms via
 * the WebSocket telemetry buffer. Color-coded by severity.
 */

import { useMemo } from 'react'
import { useWebSocketStore, type TelemetryEvent } from '../../store/useWebSocketStore'
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'
import { Activity, AlertTriangle, TrendingUp } from 'lucide-react'

interface ChartDataPoint {
  time: string
  normal: number
  suspicious: number
  threat: number
  total: number
}

export default function LiveTrafficChart({ props: _props }: { props: Record<string, unknown> }) {
  const telemetry = useWebSocketStore(s => s.telemetryBuffer)

  // Aggregate telemetry into time-bucketed chart data
  const chartData = useMemo(() => {
    if (telemetry.length === 0) return []

    const buckets = new Map<string, { normal: number; suspicious: number; threat: number }>()

    telemetry.forEach((evt: TelemetryEvent) => {
      // Bucket by seconds
      const d = new Date(evt.ts)
      const key = `${d.getMinutes().toString().padStart(2, '0')}:${d.getSeconds().toString().padStart(2, '0')}`

      if (!buckets.has(key)) {
        buckets.set(key, { normal: 0, suspicious: 0, threat: 0 })
      }
      const b = buckets.get(key)!

      if (evt.severity === 'critical' || evt.severity === 'high') {
        b.threat++
      } else if (evt.severity === 'medium') {
        b.suspicious++
      } else {
        b.normal++
      }
    })

    const data: ChartDataPoint[] = []
    buckets.forEach((v, k) => {
      data.push({
        time: k,
        normal: v.normal,
        suspicious: v.suspicious,
        threat: v.threat,
        total: v.normal + v.suspicious + v.threat,
      })
    })

    return data.slice(-30) // keep last 30 time points
  }, [telemetry])

  const totalPackets = telemetry.length
  const threatPackets = telemetry.filter(e => e.is_threat).length
  const threatPct = totalPackets > 0 ? Math.round((threatPackets / totalPackets) * 100) : 0

  const latestBytesAvg = useMemo(() => {
    const recent = telemetry.slice(-10)
    if (recent.length === 0) return 0
    return Math.round(recent.reduce((sum, e) => sum + e.bytes, 0) / recent.length)
  }, [telemetry])

  return (
    <div className="space-y-4">
      {/* Metrics row */}
      <div className="grid grid-cols-4 gap-3">
        <MiniMetric
          icon={<Activity className="w-3.5 h-3.5 text-cyan" />}
          label="Packets"
          value={totalPackets.toLocaleString()}
        />
        <MiniMetric
          icon={<AlertTriangle className="w-3.5 h-3.5 text-threat" />}
          label="Threats"
          value={threatPackets.toString()}
          highlight
        />
        <MiniMetric
          icon={<TrendingUp className="w-3.5 h-3.5 text-amber" />}
          label="Threat %"
          value={`${threatPct}%`}
        />
        <MiniMetric
          icon={<Activity className="w-3.5 h-3.5 text-green" />}
          label="Avg Bytes"
          value={latestBytesAvg.toLocaleString()}
        />
      </div>

      {/* Chart */}
      <div className="h-52 w-full">
        {chartData.length > 0 ? (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chartData} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="gradNormal" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#22c55e" stopOpacity={0.4} />
                  <stop offset="100%" stopColor="#22c55e" stopOpacity={0.02} />
                </linearGradient>
                <linearGradient id="gradSuspicious" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#f59e0b" stopOpacity={0.4} />
                  <stop offset="100%" stopColor="#f59e0b" stopOpacity={0.02} />
                </linearGradient>
                <linearGradient id="gradThreat" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#ff3e3e" stopOpacity={0.5} />
                  <stop offset="100%" stopColor="#ff3e3e" stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" strokeOpacity={0.4} />
              <XAxis
                dataKey="time"
                stroke="var(--color-text-dim)"
                fontSize={10}
                tickLine={false}
                axisLine={false}
              />
              <YAxis
                stroke="var(--color-text-dim)"
                fontSize={10}
                tickLine={false}
                axisLine={false}
                allowDecimals={false}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: 'var(--color-elevated)',
                  border: '1px solid var(--color-border)',
                  borderRadius: '8px',
                  fontSize: '11px',
                  color: 'var(--color-text)',
                }}
              />
              <Area
                type="monotone"
                dataKey="normal"
                stroke="#22c55e"
                fill="url(#gradNormal)"
                strokeWidth={2}
                dot={false}
                animationDuration={300}
              />
              <Area
                type="monotone"
                dataKey="suspicious"
                stroke="#f59e0b"
                fill="url(#gradSuspicious)"
                strokeWidth={2}
                dot={false}
                animationDuration={300}
              />
              <Area
                type="monotone"
                dataKey="threat"
                stroke="#ff3e3e"
                fill="url(#gradThreat)"
                strokeWidth={2}
                dot={false}
                animationDuration={300}
              />
            </AreaChart>
          </ResponsiveContainer>
        ) : (
          <div className="h-full flex items-center justify-center text-text-dim text-xs">
            Waiting for telemetry data...
          </div>
        )}
      </div>

      {/* Legend */}
      <div className="flex items-center justify-center gap-4 text-[10px] text-text-muted">
        <span className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-green" /> Normal
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-amber" /> Suspicious
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-threat" /> Threat
        </span>
      </div>
    </div>
  )
}

function MiniMetric({
  icon,
  label,
  value,
  highlight = false,
}: {
  icon: React.ReactNode
  label: string
  value: string
  highlight?: boolean
}) {
  return (
    <div className={`rounded-lg px-2.5 py-2 bg-black/20 border border-white/5 ${highlight ? 'threat-pulse' : ''}`}>
      <div className="flex items-center gap-1.5 mb-1">
        {icon}
        <span className="text-[9px] uppercase tracking-wider text-text-dim">{label}</span>
      </div>
      <span className={`text-sm font-bold font-mono ${highlight ? 'text-threat' : 'text-text'}`}>
        {value}
      </span>
    </div>
  )
}
