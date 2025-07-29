import { ThemeProvider } from "@/components/theme-provider";
import Dashboard from "@/pages/Dashboard";
import { ProtectedRoute } from "@/components/ProtectedRoute";

function App() {
  return (
    <ThemeProvider defaultTheme="dark" storageKey="ui-theme">
      <ProtectedRoute>
        <Dashboard />
      </ProtectedRoute>
    </ThemeProvider>
  );
}

export default App;