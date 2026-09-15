#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
push=false
load=false
image="${IMAGE:-}"
prebuild_bellman_cuda="${PREBUILD_BELLMAN_CUDA:-0}"
bellman_cuda_archs="${BELLMAN_CUDA_ARCHS:-80;89;90}"

usage() {
  cat <<'EOF'
Usage:
  scripts/vast/build-and-push-image.sh --image <image> [--push|--load]

Examples:
  scripts/vast/build-and-push-image.sh \
    --image ghcr.io/<owner>/eravm-airbender-verifier-vast:pr17-20260520 \
    --push

Options:
  --image <image>              Required unless IMAGE is set.
  --push                       Push to the registry.
  --load                       Load into local Docker instead of leaving only in buildx cache.
  --prebuild-bellman-cuda      Build era-bellman-cuda inside the image.
  --bellman-cuda-archs <list>  CMake CUDA architectures for prebuild mode.
                               Default: 80;89;90

Environment:
  IMAGE
  PREBUILD_BELLMAN_CUDA
  BELLMAN_CUDA_ARCHS
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --image)
      if [ "$#" -lt 2 ]; then
        echo "error: --image requires a value" >&2
        exit 1
      fi
      image="$2"
      shift 2
      ;;
    --push)
      push=true
      shift
      ;;
    --load)
      load=true
      shift
      ;;
    --prebuild-bellman-cuda)
      prebuild_bellman_cuda=1
      shift
      ;;
    --bellman-cuda-archs)
      if [ "$#" -lt 2 ]; then
        echo "error: --bellman-cuda-archs requires a value" >&2
        exit 1
      fi
      bellman_cuda_archs="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument '$1'" >&2
      usage
      exit 1
      ;;
  esac
done

if [ -z "$image" ]; then
  echo "error: --image is required" >&2
  usage
  exit 1
fi

if [ "$push" = true ] && [ "$load" = true ]; then
  echo "error: choose only one of --push or --load" >&2
  exit 1
fi

output_args=()
if [ "$push" = true ]; then
  output_args+=(--push)
elif [ "$load" = true ]; then
  output_args+=(--load)
fi

cd "$repo_root"

docker buildx build \
  --platform linux/amd64 \
  --file Dockerfile.vast-base \
  --tag "$image" \
  --build-arg "PREBUILD_BELLMAN_CUDA=$prebuild_bellman_cuda" \
  --build-arg "BELLMAN_CUDA_ARCHS=$bellman_cuda_archs" \
  "${output_args[@]}" \
  .

cat <<EOF

Built image: $image

For a registry push, use this image in the Vast template. Prefer a digest-pinned
reference after pushing:

  docker buildx imagetools inspect $image
EOF
