import { Outlet } from "react-router-dom";
import Sidebar from "./Sidebar";
import Header from "./Header";
import { AlertBanner } from "@/components/alerts";
import { useWebSocket } from "@/hooks";

export default function Layout() {
  useWebSocket();

  return (
    <div className="flex h-screen overflow-hidden bg-canvas-cream dark:bg-ink-black">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <Header />
        <main className="flex-1 overflow-y-auto p-6 bg-canvas-cream dark:bg-ink-black">
          <Outlet />
        </main>
      </div>
      <AlertBanner />
    </div>
  );
}
