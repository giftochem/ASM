import { Component, type ErrorInfo, type ReactNode } from "react";

interface Props {
  children: ReactNode;
}

interface State {
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error("Unhandled error in component tree", error, info);
  }

  render() {
    if (this.state.error) {
      return (
        <div role="alert" className="mx-auto mt-16 max-w-sm text-center">
          <h1 className="mb-2 text-xl font-semibold">Something went wrong</h1>
          <p className="text-slate-600">Please reload the page.</p>
        </div>
      );
    }
    return this.props.children;
  }
}
