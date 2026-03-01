import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { SecurityProvider } from "@/store/securityStore";
import { Layout } from "@/components/Layout";
import { AlertPopup } from "@/components/AlertPopup";
import Overview from "@/pages/Overview";
import BehaviorAnalytics from "@/pages/BehaviorAnalytics";
import RiskPropagation from "@/pages/RiskPropagation";
import IncidentResponse from "@/pages/IncidentResponse";
import AdminPanel from "@/pages/AdminPanel";
import LoginPortal from "@/pages/LoginPortal";
import NotFound from "./pages/NotFound";

const queryClient = new QueryClient();

// Admin routes are wrapped in SecurityProvider (WebSocket, polling, alerts)
const AdminRoutes = () => (
  <SecurityProvider>
    <AlertPopup />
    <Routes>
      <Route path="/" element={<Layout><Overview /></Layout>} />
      <Route path="/behavior" element={<Layout><BehaviorAnalytics /></Layout>} />
      <Route path="/propagation" element={<Layout><RiskPropagation /></Layout>} />
      <Route path="/incidents" element={<Layout><IncidentResponse /></Layout>} />
      <Route path="/admin" element={<Layout><AdminPanel /></Layout>} />
      <Route path="*" element={<NotFound />} />
    </Routes>
  </SecurityProvider>
);

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <BrowserRouter>
        <Routes>
          {/* Login portal is COMPLETELY isolated — no SecurityProvider, no alerts, no WebSocket */}
          <Route path="/login" element={<LoginPortal />} />
          {/* Everything else goes through admin routes with full security context */}
          <Route path="/*" element={<AdminRoutes />} />
        </Routes>
      </BrowserRouter>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
