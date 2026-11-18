import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Let other machines on the LAN load dev resources (HMR etc.) from this server.
  allowedDevOrigins: ["192.168.*.*", "10.*.*.*", "172.16.*.*", "*.ngrok-free.app", "*.ngrok-free.dev", "*.ngrok.app", "*.ngrok.dev"],
};

export default nextConfig;
