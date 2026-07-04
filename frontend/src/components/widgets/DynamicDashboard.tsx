/**
 * Q-Guardian OS — Dynamic GenUI Dashboard & Layout Engine
 *
 * Renders custom widgets (tables, forms, metric grids, and styled document templates)
 * generated dynamically by the backend LLM's payload.
 */

import { useState } from 'react'
import { useWebSocketStore } from '../../store/useWebSocketStore'
import { Terminal, Database, FileText, Settings, ShieldAlert, Cpu, HardDrive } from 'lucide-react'

interface Column {
  key: string
  label: string
}

interface Row extends Record<string, any> {
  id?: string | number
}

interface Action {
  action: string
  label: string
  style?: 'default' | 'danger'
}

interface Field {
  name: string
  label: string
  type: 'text' | 'number' | 'slider' | 'toggle'
  value: any
  min?: number
  max?: number
}

interface Block {
  type: 'title' | 'section' | 'paragraph' | 'keyvalue' | 'list'
  content: any
}

export default function DynamicDashboard({ props }: { props: Record<string, unknown> }) {
  const layoutType = (props.layoutType as string) || 'table'
  const sendAction = useWebSocketStore((s) => s.sendAction)
  
  // State for forms if layoutType is 'form'
  const initialFields = (props.fields as Field[]) || []
  const [formData, setFormData] = useState<Record<string, any>>(
    initialFields.reduce((acc, f) => ({ ...acc, [f.name]: f.value }), {})
  )

  const handleAction = (actionName: string, row: Row) => {
    sendAction({
      action: actionName,
      rowData: row,
      timestamp: new Date().toISOString(),
    })
  }

  const handleFormSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    sendAction({
      action: 'dynamic_form_submit',
      formData,
      timestamp: new Date().toISOString(),
    })
  }

  // ───────────────────────────────────────────────────────────────
  // Layout 1: Dynamic Table
  // ───────────────────────────────────────────────────────────────
  if (layoutType === 'table') {
    const columns = (props.columns as Column[]) || []
    const rows = (props.rows as Row[]) || []
    const actions = (props.actions as Action[]) || []

    return (
      <div className="space-y-4">
        <div className="overflow-x-auto rounded-lg border border-white/5 bg-deep/30">
          <table className="w-full text-left border-collapse text-xs font-sans">
            <thead>
              <tr className="border-b border-white/5 bg-white/[0.02]">
                {columns.map((col) => (
                  <th key={col.key} className="p-3 font-semibold text-text-muted">
                    {col.label}
                  </th>
                ))}
                {actions.length > 0 && <th className="p-3 text-right">Actions</th>}
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 ? (
                <tr>
                  <td colSpan={columns.length + (actions.length > 0 ? 1 : 0)} className="p-8 text-center text-text-dim">
                    No records found
                  </td>
                </tr>
              ) : (
                rows.map((row, rIdx) => (
                  <tr key={row.id || rIdx} className="border-b border-white/5 hover:bg-white/[0.01] transition-colors">
                    {columns.map((col) => (
                      <td key={col.key} className="p-3 font-mono text-text">
                        {row[col.key]}
                      </td>
                    ))}
                    {actions.length > 0 && (
                      <td className="p-3 text-right space-x-1.5 whitespace-nowrap">
                        {actions.map((act) => (
                          <button
                            key={act.action}
                            onClick={() => handleAction(act.action, row)}
                            className={`px-2 py-1 rounded text-[10px] font-semibold transition-all cursor-pointer ${
                              act.style === 'danger'
                                ? 'bg-threat/10 border border-threat/30 text-threat hover:bg-threat/20'
                                : 'bg-cyan/15 border border-cyan/30 text-cyan hover:bg-cyan/25'
                            }`}
                          >
                            {act.label}
                          </button>
                        ))}
                      </td>
                    )}
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    )
  }

  // ───────────────────────────────────────────────────────────────
  // Layout 2: Dynamic Metric Cards
  // ───────────────────────────────────────────────────────────────
  if (layoutType === 'cards') {
    const data = (props.data as any[]) || []

    return (
      <div className="grid grid-cols-2 gap-3">
        {data.map((card, idx) => (
          <div key={idx} className="bg-black/20 border border-white/5 rounded-xl p-3.5 flex flex-col justify-between">
            <span className="text-[10px] text-text-dim uppercase tracking-wider font-semibold">
              {card.label}
            </span>
            <div className="flex items-baseline justify-between mt-1">
              <span className="text-lg font-bold font-mono text-text">
                {card.value}
              </span>
              {card.trend && (
                <span className={`text-[10px] font-medium font-mono ${
                  card.trendColor === 'green' ? 'text-green' : card.trendColor === 'red' ? 'text-threat' : 'text-text-muted'
                }`}>
                  {card.trend}
                </span>
              )}
            </div>
          </div>
        ))}
      </div>
    )
  }

  // ───────────────────────────────────────────────────────────────
  // Layout 3: Dynamic Form
  // ───────────────────────────────────────────────────────────────
  if (layoutType === 'form') {
    const fields = (props.fields as Field[]) || []

    return (
      <form onSubmit={handleFormSubmit} className="space-y-4">
        {fields.map((f) => (
          <div key={f.name} className="space-y-1.5">
            <label className="text-xs font-semibold text-text-muted block">{f.label}</label>
            {f.type === 'toggle' ? (
              <div className="flex items-center">
                <button
                  type="button"
                  onClick={() => setFormData({ ...formData, [f.name]: !formData[f.name] })}
                  className={`w-10 h-5.5 rounded-full p-0.5 transition-colors cursor-pointer ${
                    formData[f.name] ? 'bg-cyan' : 'bg-deep'
                  }`}
                >
                  <div className={`bg-void w-4.5 h-4.5 rounded-full shadow-md transform duration-200 ease-in-out ${
                    formData[f.name] ? 'translate-x-4.5' : 'translate-x-0'
                  }`} />
                </button>
              </div>
            ) : f.type === 'slider' ? (
              <div className="flex items-center gap-3">
                <input
                  type="range"
                  min={f.min || 0}
                  max={f.max || 100}
                  value={formData[f.name] || 0}
                  onChange={(e) => setFormData({ ...formData, [f.name]: parseInt(e.target.value) })}
                  className="flex-1 h-1 bg-deep rounded-lg appearance-none cursor-pointer accent-cyan"
                />
                <span className="text-xs font-mono text-cyan w-10 text-right">{formData[f.name]}</span>
              </div>
            ) : (
              <input
                type={f.type}
                value={formData[f.name] || ''}
                onChange={(e) => setFormData({ ...formData, [f.name]: e.target.value })}
                className="w-full px-3 py-2 bg-deep border border-border rounded-lg text-xs text-text focus:outline-none focus:border-cyan/40"
              />
            )}
          </div>
        ))}
        <button
          type="submit"
          className="w-full py-2 bg-cyan text-void hover:bg-cyan/90 transition-all font-semibold rounded-lg text-xs cursor-pointer"
        >
          Submit Form
        </button>
      </form>
    )
  }

  // ───────────────────────────────────────────────────────────────
  // Layout 4: Dynamic Document / Resume Preview
  // ───────────────────────────────────────────────────────────────
  if (layoutType === 'document') {
    const blocks = (props.blocks as Block[]) || []

    return (
      <div className="bg-black/40 border border-white/5 rounded-2xl p-6 space-y-5 text-sans text-xs select-text selection:bg-cyan/30 selection:text-white max-h-[500px] overflow-y-auto custom-scrollbar shadow-inner">
        {blocks.map((block, idx) => {
          if (block.type === 'title') {
            return (
              <div key={idx} className="border-b border-cyan/20 pb-3 text-center">
                <h1 className="text-base font-extrabold text-white tracking-wide">{block.content}</h1>
              </div>
            )
          }
          if (block.type === 'section') {
            return (
              <h2 key={idx} className="text-xs font-bold text-cyan uppercase tracking-wider border-b border-white/5 pb-1 mt-4">
                {block.content}
              </h2>
            )
          }
          if (block.type === 'paragraph') {
            return (
              <p key={idx} className="text-text-muted leading-relaxed font-light">
                {block.content}
              </p>
            )
          }
          if (block.type === 'keyvalue') {
            const dataObj = block.content as Record<string, string>
            return (
              <div key={idx} className="grid grid-cols-2 gap-x-6 gap-y-2 bg-white/[0.01] border border-white/5 p-3 rounded-lg">
                {Object.entries(dataObj).map(([key, val]) => (
                  <div key={key} className="flex justify-between border-b border-white/5 pb-1 last:border-b-0">
                    <span className="font-semibold text-text-dim">{key}</span>
                    <span className="text-text font-mono text-right">{val}</span>
                  </div>
                ))}
              </div>
            )
          }
          if (block.type === 'list') {
            const listItems = block.content as string[]
            return (
              <ul key={idx} className="list-disc list-inside space-y-1.5 pl-2 text-text-muted font-light">
                {listItems.map((item, itemIdx) => (
                  <li key={itemIdx} className="leading-relaxed">
                    {item}
                  </li>
                ))}
              </ul>
            )
          }
          return null
        })}
      </div>
    )
  }

  return (
    <div className="p-4 text-center text-text-dim text-xs">
      Unsupported dynamic layout: {layoutType}
    </div>
  )
}
