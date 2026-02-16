import { useEffect } from 'react';
import { useAppStore } from '@/stores/appStore';
import { api } from '@/services/api';
import LoginPage from '@/pages/LoginPage';

export function ProtectedRoute({ children }: { children: React.ReactNode }) {
    const isAuthenticated = useAppStore(state => state.isAuthenticated);
    const authRequired = useAppStore(state => state.authRequired);
    const setAuthRequired = useAppStore(state => state.setAuthRequired);

    useEffect(() => {
        // Only check once (when authRequired is still null)
        if (authRequired === null) {
            api.checkAuth()
                .then(res => setAuthRequired(res.data.auth_required))
                .catch(() => setAuthRequired(true)); // Default to requiring auth on error
        }
    }, [authRequired, setAuthRequired]);

    // Still checking auth status
    if (authRequired === null) {
        return null;
    }

    // Server has auth disabled — allow access without login
    if (!authRequired) {
        return <>{children}</>;
    }

    // Auth is required but user is not authenticated
    if (!isAuthenticated) {
        return <LoginPage />;
    }

    return <>{children}</>;
}
