/** @type {import('next').NextConfig} */
const nextConfig = {
  transpilePackages: ['cytoscape'],
  eslint: {
    ignoreDuringBuilds: true,
  },
  typescript: {
    ignoreBuildErrors: false,
  },
};

export default nextConfig;
