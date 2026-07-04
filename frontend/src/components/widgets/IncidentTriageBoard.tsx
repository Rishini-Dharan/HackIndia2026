/**
 * Q-Guardian OS — Incident Triage Board Widget
 *
 * A Kanban-style board or data table listing active anomalies.
 * Allows operators to quickly Acknowledge or Isolate threats.
 */

import { useState } from 'react'
import { AlertCircle, CheckCircle, ShieldAlert, Clock } from 'lucide-react'
import { useWebSocketStore } from '../../store/useWebSocketStore'

interface Incident {
  id: string
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  sourceIp: string
  targetIp: string
  timestamp: string
  status: 'new' | 'acknowledged' | 'isolated'
}

export default function IncidentTriageBoard({ props }: { props: Record<string, unknown> }) {
  const initialIncidents = (props.incidents as Incident[]) || [
    { id: 'INC-101', title: 'Volumetric DDoS Detected', severity: 'critical', sourceIp: '45.33.12.99', targetIp: '192.168.1.10', timestamp: new Date().toISOString(), status: 'new' },
    { id: 'INC-102', title: 'Repeated SQLi Attempts', severity: 'high', sourceIp: '185.15.22.1', targetIp: '192.168.1.15', timestamp: new Date(Date.now() - 60000).toISOString(), status: 'new' },
    { id: 'INC-103', title: 'Anomalous Data Exfiltration', severity: 'medium', sourceIp: '10.0.0.5', targetIp: '198.51.100.22', timestamp: new Date(Date.now() - 180000).toISOString(), status: 'acknowledged' }
  ]

  const [incidents, setIncidents] = useState<Incident[]>(initialIncidents)
  const sendAction = useWebSocketStore(s => s.sendAction)

  const updateStatus = (id: string, newStatus: 'acknowledged' | 'isolated') => {
    setIncidents(prev => prev.map(inc => inc.id === id ? { ...inc, status: newStatus } : inc))
    
    // Notify the backend LLM that we took action on an incident
    sendAction({
      action: `incident_${newStatus}`,
      incidentId: id,
      notes: `Operator transitioned incident to ${newStatus}`
    })
  }

  const getSeverityColor = (sev: string) => {
    switch (sev) {
      case 'critical': return 'text-threat bg-threat/10 border-threat/20'
      case 'high': return 'text-amber bg-amber/10 border-amber/20'
      case 'medium': return 'text-purple bg-purple/10 border-purple/20'
      default: return 'text-green bg-green/10 border-green/20'
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between mb-2 border-b border-border pb-2">
        <h4 className="text-xs font-semibold text-text-muted flex items-center gap-2">
          <AlertCircle className="w-4 h-4 text-cyan" />
          Active Incidents
        </h4>
        <span className="text-[10px] bg-deep px-2 py-0.5 rounded-full text-text-dim">
          {incidents.filter(i => i.status === 'new').length} Needs Attention
        </span>
      </div>

      <div className="space-y-3">
        {incidents.map(inc => (
          <div key={inc.id} className="bg-black/20 border border-white/5 rounded-lg p-3 hover:border-white/10 transition-colors">
            <div className="flex justify-between items-start mb-2">
              <div>
                <div className="flex items-center gap-2">
                  <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border uppercase tracking-wider ${getSeverityColor(inc.severity)}`}>
                    {inc.severity}
                  </span>
                  <span className="text-xs font-semibold text-text">{inc.title}</span>
                </div>
                <div className="text-[10px] text-text-dim mt-1.5 flex items-center gap-3 font-mono">
                  <span>{inc.sourceIp} → {inc.targetIp}</span>
                  <span className="flex items-center gap-1"><Clock className="w-3 h-3" /> {new Date(inc.timestamp).toLocaleTimeString()}</span>
                </div>
              </div>
              <div className="text-right">
                <span className="text-[10px] text-text-muted uppercase tracking-wider block mb-1">Status</span>
                <span className={`text-[11px] font-medium ${
                  inc.status === 'new' ? 'text-amber' : 
                  inc.status === 'isolated' ? 'text-green' : 'text-cyan'
                }`}>
                  {inc.status.toUpperCase()}
                </span>
              </div>
            </div>

            {inc.status === 'new' && (
              <div className="flex gap-2 mt-3 pt-3 border-t border-white/5">
                <button 
                  onClick={() => updateStatus(inc.id, 'acknowledged')}
                  className="flex-1 flex items-center justify-center gap-1.5 py-1.5 bg-deep hover:bg-white/5 border border-white/10 rounded text-[11px] font-medium text-text-muted hover:text-text transition-colors cursor-pointer"
                >
                  <CheckCircle className="w-3.5 h-3.5" />
                  Acknowledge
                </button>
                <button 
                  onClick={() => updateStatus(inc.id, 'isolated')}
                  className="flex-1 flex items-center justify-center gap-1.5 py-1.5 bg-threat/10 hover:bg-threat/20 border border-threat/30 rounded text-[11px] font-medium text-threat transition-colors cursor-pointer"
                >
                  <ShieldAlert className="w-3.5 h-3.5" />
                  Isolate Host
                </button>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
