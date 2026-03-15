import { Outlet } from "react-router-dom";
import Sidebar from "./Sidebar";
import Header from "./Header";
import { AlertBanner } from "@/components/alerts";
import { useWebSocket } from "@/hooks";

export default function Layout() {
  useWebSocket();

  return (
    /* Pure white / pitch black shell — sidebar + content share the same bg token */
    <div className="flex h-screen overflow-hidden bg-gray-50 dark:bg-black">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <Header />
        <main className="flex-1 overflow-y-auto p-6 bg-gray-50 dark:bg-[#0a0a0a]">
          <Outlet />
        </main>
      </div>
      <AlertBanner />
    </div>
  );
}
