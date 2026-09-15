# Version manifest for the Trivy scanner used by .github/workflows/security.yml.
#
# Nothing builds this image. It exists so Dependabot's docker ecosystem can see
# the pinned Trivy version and open a PR when a new release ships (subject to the
# cooldown in .github/dependabot.yml). The install-trivy action reads the tag from
# the FROM line below, downloads the matching release tarball and verifies its
# SLSA provenance before use.
#
# Keep the FROM line exactly in this shape (no digest, no stage name): the
# install action parses it with an anchored sed expression.
FROM ghcr.io/aquasecurity/trivy:0.74.0

# Never built, but security.yml's trivy-config job scans every Dockerfile in the
# repo and flags a missing non-root USER (DS-0002, HIGH).
USER 65534:65534
