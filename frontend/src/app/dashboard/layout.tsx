import { AuthGuard } from "@/components/auth/auth-guard";
import { Header } from "@/components/layout/header";
import { Sidebar } from "@/components/layout/sidebar";

export default function DashboardLayout({ children }: LayoutProps<"/dashboard">) {
  return (
    <AuthGuard>
      <div className="flex min-h-screen">
        <Sidebar />
        <div className="flex min-w-0 flex-1 flex-col">
          <Header />
          <main className="flex-1 px-4 py-6 sm:px-6 lg:px-8">
            <div className="mx-auto w-full max-w-6xl space-y-6">{children}</div>
          </main>
        </div>
      </div>
    </AuthGuard>
  );
}
