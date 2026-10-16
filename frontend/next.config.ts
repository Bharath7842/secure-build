import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Let other machines on the LAN load dev resources (HMR etc.) from this server.
  allowedDevOrigins: ["192.168.*.*", "10.*.*.*", "172.16.*.*"],
};

export default nextConfig;
