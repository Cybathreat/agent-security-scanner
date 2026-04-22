import type { Metadata } from "next";
import "./globals.css";
import { Sidebar } from "@/components/layout/sidebar";
import { Providers } from "@/components/layout/providers";

export const metadata: Metadata = {
  title: "Singularity",
  description: "Security scanning dashboard for AI agents, RAG pipelines, and agent frameworks",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark h-full">
      <head>
        <link
          href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600;700&family=Fira+Sans:wght@400;500;600;700&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className="min-h-full bg-background text-foreground font-sans antialiased">
        <Providers>
          <div className="flex h-full">
            <Sidebar />
            <main className="flex-1 md:ml-56 p-6">
              {children}
            </main>
          </div>
        </Providers>
      </body>
    </html>
  );
}