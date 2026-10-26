import { Component, type ErrorInfo, type ReactNode } from 'react'
import { Shell } from './components/Shell'
import { useRoute } from './router'
import { EngineProvider } from './state/engine'
import Analytics from './pages/Analytics'
import Diagnostics from './pages/Diagnostics'
import Integrity from './pages/Integrity'
import Lab from './pages/Lab'
import PipelinePage from './pages/PipelinePage'
import Workspace from './pages/Workspace'

class Boundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null }
  static getDerivedStateFromError(error: Error) {
    return { error }
  }
  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('UI error', error, info.componentStack)
  }
  render() {
    if (!this.state.error) return this.props.children
    return (
      <div role="alert" className="mx-auto mt-16 max-w-lg rounded-md border border-bad/50 bg-deck p-6">
        <h1 className="text-xl font-semibold text-bad">Something went wrong in the interface</h1>
        <p className="mt-2 text-slate">The engine is unaffected. Reload the page to continue. Message: {this.state.error.message}</p>
        <button className="btn mt-4" onClick={() => window.location.reload()}>Reload</button>
      </div>
    )
  }
}

function Page() {
  const route = useRoute()
  switch (route) {
    case '/pipeline':
      return <PipelinePage />
    case '/integrity':
      return <Integrity />
    case '/lab':
      return <Lab />
    case '/analytics':
      return <Analytics />
    case '/diagnostics':
      return <Diagnostics />
    default:
      return <Workspace />
  }
}

export default function App() {
  return (
    <Boundary>
      <EngineProvider>
        <Shell>
          <Page />
        </Shell>
      </EngineProvider>
    </Boundary>
  )
}
