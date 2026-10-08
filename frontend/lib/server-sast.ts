function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(
      `Missing required environment variable ${name}. ` +
        "Copy frontend/.env.local.example to frontend/.env.local and set it."
    );
  }
  return value;
}

/**
 * Proxies a request to the FastAPI SAST backend, attaching the server-only
 * bearer token. Never import this module from client components.
 */
export async function sastFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const base = requiredEnv("SAST_API_URL");
  const token = requiredEnv("SAST_API_TOKEN");

  return fetch(`${base}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
      ...(init.headers || {}),
    },
    cache: "no-store",
  });
}
