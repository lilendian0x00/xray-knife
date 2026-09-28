import { ThemeProvider } from "@/components/theme-provider";
import { I18nProvider } from "@/i18n";
import { Toaster } from "@/components/ui/sonner";
import { ErrorBoundary } from "@/components/common/ErrorBoundary";
import { AuthGate } from "@/components/AuthGate";
import Dashboard from "@/pages/Dashboard";

function App() {
    return (
        <ThemeProvider defaultTheme="system" storageKey="ui-theme">
            <I18nProvider>
                <Toaster position="top-center" closeButton richColors={false} />
                <ErrorBoundary area="The panel">
                    <AuthGate>
                        <Dashboard />
                    </AuthGate>
                </ErrorBoundary>
            </I18nProvider>
        </ThemeProvider>
    );
}

export default App;
