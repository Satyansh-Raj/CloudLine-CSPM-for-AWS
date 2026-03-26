import {
  createBrowserRouter,
  Navigate,
  RouterProvider,
} from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { lazy, Suspense } from "react";
import { AlertProvider } from "@/context/AlertContext";
import { AccountProvider } from "@/context/AccountContext";
import { RegionProvider } from "@/context/RegionContext";
import { Layout } from "@/components/layout";
import {
  DashboardPage,
  ViolationsPage,
  ViolationDetailPage,
  ResolvedIssuesPage,
  TrendsPage,
  ExecutiveSummaryPage,
  PoliciesPage,
  InventoryPage,
  CategoryResourcesPage,
  ResourceDetailPage,
  CompliancePage,
  ResolvedDetailPage,
} from "@/pages";

const IamGraphPage = lazy(() => import("@/pages/IamGraphPage"));

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 10_000,
    },
  },
});

const router = createBrowserRouter([
  {
    path: "/",
    element: <Layout />,
    children: [
      {
        index: true,
        element: <Navigate to="/dashboard" replace />,
      },
      {
        path: "dashboard",
        element: <DashboardPage />,
      },
      {
        path: "violations",
        element: <ViolationsPage />,
      },
      {
        path: "violations/:checkId/:resource",
        element: <ViolationDetailPage />,
      },
      {
        path: "trends",
        element: <TrendsPage />,
      },
      {
        path: "executive",
        element: <ExecutiveSummaryPage />,
      },
      {
        path: "policies",
        element: <PoliciesPage />,
      },
      {
        path: "resolved",
        element: <ResolvedIssuesPage />,
      },
      {
        path: "resolved/:checkId/:resource",
        element: <ResolvedDetailPage />,
      },
      {
        path: "inventory",
        element: <InventoryPage />,
      },
      {
        path: "inventory/:category",
        element: <CategoryResourcesPage />,
      },
      {
        path: "inventory/detail",
        element: <ResourceDetailPage />,
      },
      {
        path: "compliance",
        element: <CompliancePage />,
      },
      {
        path: "iam-graph",
        element: (
          <Suspense
            fallback={
              <div className="p-8 animate-pulse text-sm text-gray-400">
                Loading IAM Graph…
              </div>
            }
          >
            <IamGraphPage />
          </Suspense>
        ),
      },
    ],
  },
]);

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AlertProvider>
        <AccountProvider>
          <RegionProvider>
            <RouterProvider router={router} />
          </RegionProvider>
        </AccountProvider>
      </AlertProvider>
    </QueryClientProvider>
  );
}

export default App;
