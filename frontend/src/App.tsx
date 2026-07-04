/**
 * Q-Guardian OS — Root Application Component
 */

import { useEffect } from 'react'
import { useWebSocketStore } from './store/useWebSocketStore'
import Sidebar from './components/Sidebar'
import ChatCanvas from './components/ChatCanvas'

export default function App() {
  const connect = useWebSocketStore(s => s.connect)

  useEffect(() => {
    connect()
    return () => {
      // cleanup handled by store
    }
  }, [connect])

  return (
    <div className="flex h-dvh w-full bg-void overflow-hidden">
      <Sidebar />
      <main className="flex-1 flex flex-col min-w-0">
        <ChatCanvas />
      </main>
    </div>
  )
}
