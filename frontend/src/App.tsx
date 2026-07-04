/**
 * Q-Guardian OS — Root Application Component
 */

import { useEffect } from 'react'
import { useWebSocketStore } from './store/useWebSocketStore'
import Sidebar from './components/Sidebar'
import ChatCanvas from './components/ChatCanvas'
import InvestigationBanner from './components/InvestigationBanner'
import WidgetRenderer from './components/WidgetRenderer'

export default function App() {
  const connect = useWebSocketStore(s => s.connect)
  const activeWorkspace = useWebSocketStore(s => s.activeWorkspace)
  const mountedWidgets = useWebSocketStore(s => s.mountedWidgets)

  useEffect(() => {
    connect()
    return () => {
      // cleanup handled by store
    }
  }, [connect])

  return (
    <div className="flex h-dvh w-full bg-void overflow-hidden">
      <Sidebar />
      <main className="flex-1 flex min-w-0">
        {activeWorkspace ? (
          <div className="grid grid-cols-12 h-full w-full">
            {/* Left Column: Chat Conversation Canvas */}
            <div className="col-span-4 border-r border-border h-full flex flex-col min-w-0">
              <ChatCanvas />
            </div>

            {/* Right Column: Dynamic Investigation Workspace */}
            <div className="col-span-8 flex flex-col p-6 space-y-6 overflow-y-auto h-full bg-abyss/45 custom-scrollbar">
              <InvestigationBanner />
              
              <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
                {mountedWidgets.map(widget => (
                  <div key={widget.id} className="widget-enter">
                    <WidgetRenderer descriptor={widget} />
                  </div>
                ))}
              </div>
            </div>
          </div>
        ) : (
          <div className="flex-1 flex flex-col min-w-0">
            <ChatCanvas />
          </div>
        )}
      </main>
    </div>
  )
}
