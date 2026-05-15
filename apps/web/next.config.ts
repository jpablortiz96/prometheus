import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  allowedDevOrigins: ["localhost", "127.0.0.1", "192.168.56.1"],
  experimental: {
    externalDir: true,
  },
  transpilePackages: ["@prometheus/shared"],
};

export default nextConfig;
