The signer UI is built inside the Docker image (see Dockerfile: wasm + ui
stages) and embedded here at image build time. It is no longer committed.

This placeholder keeps `go:embed dist` compiling for local builds and tests.
With no index.html present the server falls back to its template UI. To run
the React UI locally: `cd ui && npm ci && npm run build`, which writes the
build here (git-ignored).
