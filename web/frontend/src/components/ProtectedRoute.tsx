import { useAppStore } from '@/stores/appStore';
import LoginPage from '@/pages/LoginPage';

export function ProtectedRoute({ children }: { children: React.ReactNode }) {
    const isAuthenticated = useAppStore(state => state.isAuthenticated);

    if (!isAuthenticated) {
        return <LoginPage />;
    }

    return <>{children}</>;
}