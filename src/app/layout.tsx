import type { Metadata, Viewport } from "next";
import { Analytics } from "@vercel/analytics/next";
import "./globals.css";

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
};

export const metadata: Metadata = {
  title: "SecAsk: Security Knowledge RAG",
  description:
    "Unified security knowledge platform. Index ATT&CK, Sigma, NVD, NIST, and your own docs. Browser-native RAG. No server. API keys encrypted locally.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      {/* Prevent flash of wrong theme on load */}
      <head>
        {/* SecAsk always uses the Papercut Layers (warm cream) theme */}
        <script dangerouslySetInnerHTML={{ __html: `(function(){try{document.documentElement.setAttribute('data-theme','light');}catch(e){}})()` }} />
      </head>
      <body suppressHydrationWarning>
        {children}
        <Analytics />
      </body>
    </html>
  );
}
