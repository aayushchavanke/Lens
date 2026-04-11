import "./globals.css";

export const metadata = {
  title: "The Obsidian Lens - Network Forensic Tool",
  description:
    "Minimalistic professional network forensic tool. 49-parameter behavioral analysis, White/Black identity categorization, and persistent fingerprint tracking.",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
