# Frontend Documentation

This folder documents the `frontend/` application of Q-Guardian OS.

The frontend is a React/Vite application with a dynamic investigation console. It is built around a WebSocket-driven state store and a widget registry that renders backend-provided layout commands.

## Core Files

- `src/App.tsx` — root layout, split-screen app shell, and investigation workspace rendering
- `src/store/useWebSocketStore.ts` — Zustand store for WebSocket connection, messages, telemetry, workspaces, and mounted widgets
- `src/components/ChatCanvas.tsx` — chat interface, message list, typing state, and inline widget rendering
- `src/components/Sidebar.tsx` — session metrics, simulation controls, and quick action buttons
- `src/components/WidgetRenderer.tsx` — dynamic widget resolver and interactive widget container
- `src/components/widgets/` — widget implementations for charting, topology, mitigation, triage boards, and dynamic dashboards

## Feature Summary

- Uses `useWebSocketStore` to maintain:
  - connection state
  - chat history
  - active investigation workspace
  - mounted widgets
  - telemetry event buffer
- `App.tsx` renders either a single-pane chat or a split-pane chat + workspace depending on whether a workspace is mounted.
- `ChatCanvas.tsx` supports natural conversation plus inline mounted widgets when the workspace is not active.
- `WidgetRenderer.tsx` maps backend widget descriptors to React components and handles minimize/close controls.
- The widget layer is extensible: developers can add new components to `src/components/widgets` and register them in `WidgetRenderer.tsx`.

## Widget Components

- `LiveTrafficChart` — time-series traffic chart built with Recharts and live telemetry data
- `ThreatTopology` — SVG node-link attack topology visualization
- `MitigationAction` — interactive mitigation form for blocking or quarantining IPs
- `IncidentTriageBoard` — incident list with acknowledge/isolate actions
- `DynamicDashboard` — generic layout engine for tables, cards, forms, and document-style payloads

## Notes

- The app connects to `ws://localhost:8000/ws/chat` by default.
- The frontend uses React 19, Tailwind CSS, Zustand, Framer Motion, and Recharts.
- Messages received from the backend may include widget mounts and workspace instructions.
