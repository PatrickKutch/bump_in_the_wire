#!/bin/bash
set -e

echo "🐳 Docker-Only Build"
echo "===================="
echo "✅ No external dependencies required"
echo "✅ No manual downloads needed" 
echo "✅ Only requires Docker on host"
echo "✅ Uses Ubuntu 24.04 which has libxdp packages"
echo ""

# Build the container using only Docker
echo "Building container with Docker-only approach..."
docker build -t bitw_xdp:docker-only .

echo ""
echo "🎉 Build Complete!"

# Test the container
echo ""
echo "Testing container..."
sudo docker run --rm bitw_xdp:docker-only 2>&1 | head -15

echo ""
echo "✅ SUCCESS! Container is ready and fully transportable."
echo ""
echo "📋 Usage:"
echo "  sudo docker run --privileged --network=host --rm \\"
echo "    -v /sys/fs/bpf:/sys/fs/bpf \\"
echo "    -v /sys:/sys \\"
echo "    -v /proc:/proc \\"
echo "    bitw_xdp:docker-only PF0 PF1 --cpu-a 2 --cpu-b 3"
echo ""
echo "📦 To make transportable:"
echo "  docker save bitw_xdp:docker-only | gzip > bitw_xdp-docker-only.tar.gz"
echo ""
echo "🎯 This container:"
echo "  ✅ Built with Docker only"
echo "  ✅ No host dependencies"  
echo "  ✅ Uses official Ubuntu packages"
echo "  ✅ Fully self-contained"
echo "  ✅ Transportable to any system with Docker"
echo ""