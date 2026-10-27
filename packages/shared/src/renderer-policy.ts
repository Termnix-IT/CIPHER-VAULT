export type RendererPolicyMode = "web" | "desktop" | "development";

export function localDevelopmentUrl(value: string) {
  const url = new URL(value);
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password ||
      !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)) {
    throw new Error("開発画面のURLにはローカルのHTTP/HTTPSを指定してください");
  }
  return url;
}

// The HTML meta policy also works for file://. frame-ancestors is added in HTTP headers.
export function rendererContentSecurityPolicy(mode: RendererPolicyMode, developmentUrl?: string) {
  const development = mode === "development";
  let connections = mode === "desktop" ? "'none'" : "'self'";
  if (development) {
    const url = localDevelopmentUrl(developmentUrl!);
    const protocol = url.protocol === "https:" ? "wss:" : "ws:";
    const port = url.port ? `:${url.port}` : "";
    connections += ` ${protocol}//localhost${port} ${protocol}//127.0.0.1${port} ${protocol}//[::1]${port}`;
  }
  return [
    "default-src 'none'", "base-uri 'none'", "object-src 'none'", "frame-src 'none'", "form-action 'none'",
    `script-src 'self'${development ? " 'unsafe-inline'" : ""}`,
    "style-src 'self' 'unsafe-inline'", `style-src-elem 'self'${development ? " 'unsafe-inline'" : ""}`,
    "style-src-attr 'unsafe-inline'", "img-src 'self' data: blob:", "font-src 'self'",
    "worker-src 'none'", `connect-src ${connections}`
  ].join("; ");
}
