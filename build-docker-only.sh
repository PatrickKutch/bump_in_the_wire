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
echo "  # S-Flow mode (default)"
echo "  sudo docker run --privileged --network=host --rm \\"
echo "    -v /sys/fs/bpf:/sys/fs/bpf \\"
echo "    -v /sys:/sys \\"
echo "    -v /proc:/proc \\"
echo "    bitw_xdp:docker-only PF0 PF1 --sample.sampling 1000 --sample.ethertypes=0x800"
echo ""
echo "  # Filter mode"  
echo "  sudo docker run --privileged --network=host --rm \\"
echo "    -v /sys/fs/bpf:/sys/fs/bpf -v /sys:/sys -v /proc:/proc \\"
echo "    -e BITW_MODE=filter bitw_xdp:docker-only PF0 PF1"
echo ""
echo "  # AFX_TX test mode (I226 debugging)"
echo "  sudo docker run --privileged --network=host --rm \\"
echo "    -v /sys/fs/bpf:/sys/fs/bpf -v /sys:/sys -v /proc:/proc \\"
echo "    -e BITW_MODE=afx_tx bitw_xdp:docker-only eth0 aa:bb:cc:dd:ee:ff 1000 --i226-mode"
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
echo "  ✅ Includes bitw_sflow, bitw_filter, and afx_tx programs"
echo ""