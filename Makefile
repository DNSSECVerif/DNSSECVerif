# Makefile for DNSSECVerif (ACM CCS 2026; GPL-3.0-only)
#
# Targets:
#   make all          Run every model, including the long-running cache model
#   make quick        Run every model except the cache model
#   make parse-only   Partial parse checks; .pv syntax is NOT checked
#   make clean        Remove the results/ directory
#   make docker       Build the Docker image (single-arch, host platform)
#   make docker-multi Build a multi-arch image (linux/amd64 + linux/arm64)
#   make docker-quick Run the quick set inside Docker
#
# Non-Docker targets need Tamarin 1.10.0 and ProVerif 2.04. See README.md.

SHELL := /bin/bash
DOCKER_IMAGE := dnssecverif

.PHONY: all quick parse-only clean docker docker-multi docker-quick

# Full registry, including the long-running bounded cache model.
all:
	./run_all.sh --full

# Every model except the cache model (P1-P6, P8-P9); see QUICK_MODELS in run_all.sh.
quick:
	./run_all.sh --quick

# Partial parse/export mode; does not parse checked-in ProVerif files.
parse-only:
	./run_all.sh --parse-only

# Remove generated results.
clean:
	rm -rf results/

# Build the Docker image for the host platform (amd64 or arm64).
docker:
	docker build -t $(DOCKER_IMAGE) .

# Build a multi-arch image for linux/amd64 and linux/arm64 via buildx.
# Requires `docker buildx create --use --name multibuild` (one-time).
# arm64 builds Tamarin from source, so this is slow on the first arm64 build.
docker-multi:
	docker buildx build --platform linux/amd64,linux/arm64 -t $(DOCKER_IMAGE) .

# Run the quick verification inside the Docker image.
# Results are written to ./results (mounted from the host).
docker-quick:
	docker run --rm -v $(CURDIR)/results:/app/results $(DOCKER_IMAGE) --quick
