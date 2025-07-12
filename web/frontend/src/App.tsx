import { ThemeProvider } from "@/components/theme-provider";
import Dashboard from "@/pages/Dashboard";

function App() {
  return (
    <ThemeProvider defaultTheme="dark" storageKey="vite-ui-theme">
      <main className="min-h-screen bg-background text-foreground">
        <div className="container mx-auto p-4 md:p-8">
          <Dashboard />
        </div>
      </main>
    </ThemeProvider>
  );
}

export default App;