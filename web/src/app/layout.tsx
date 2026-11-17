import type { ReactNode } from "react";

export const metadata = {
  title: "MyCloud",
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body
        style={{
          margin: 0,
          fontFamily: "system-ui, -apple-system, Segoe UI, sans-serif",
          background: "#0f1115",
          color: "#e6e8ee",
        }}
      >
        {children}
      </body>
    </html>
  );
}
