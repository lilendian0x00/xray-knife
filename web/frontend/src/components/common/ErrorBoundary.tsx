import { Component, type ErrorInfo, type ReactNode } from "react";
import { AlertTriangle, RotateCcw } from "lucide-react";
import { Button } from "@/components/ui/button";

interface Props {
    children: ReactNode;
    /** Label for the part of the UI that crashed, e.g. "HTTP tester". */
    area?: string;
    /** Changing this key resets the boundary (e.g. on page change). */
    resetKey?: string;
}

interface State {
    error: Error | null;
    key?: string;
}

export class ErrorBoundary extends Component<Props, State> {
    state: State = { error: null, key: this.props.resetKey };

    static getDerivedStateFromError(error: Error): Partial<State> {
        return { error };
    }

    static getDerivedStateFromProps(props: Props, state: State): Partial<State> | null {
        if (props.resetKey !== state.key) return { error: null, key: props.resetKey };
        return null;
    }

    componentDidCatch(error: Error, info: ErrorInfo) {
        console.error(`UI error in ${this.props.area ?? "app"}:`, error, info.componentStack);
    }

    render() {
        if (!this.state.error) return this.props.children;
        return (
            <div role="alert" className="mx-auto my-10 max-w-lg rounded-lg border border-fail/40 bg-fail/5 p-6">
                <div className="flex items-start gap-3">
                    <AlertTriangle className="mt-0.5 size-5 shrink-0 text-fail" aria-hidden />
                    <div className="min-w-0 space-y-2">
                        <p className="font-medium">{this.props.area ? `${this.props.area} stopped working` : "Something broke in the panel"}</p>
                        <p className="text-sm text-muted-foreground">
                            Running services are not affected. Reload this view to continue; if it keeps happening, the message below helps a bug report.
                        </p>
                        <pre className="max-h-32 overflow-auto rounded bg-muted p-2 font-mono text-xs">{this.state.error.message}</pre>
                        <Button size="sm" variant="outline" onClick={() => this.setState({ error: null })}>
                            <RotateCcw /> Reload view
                        </Button>
                    </div>
                </div>
            </div>
        );
    }
}
