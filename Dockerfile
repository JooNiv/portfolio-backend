FROM rust:slim AS build
WORKDIR /app

# Install build dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends pkg-config libssl-dev

# Copy dependency files first to build dependencies (leveraging cache layers)
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && \
    echo 'fn main() { println!("Placeholder"); }' > src/main.rs && \
    cargo build --release

# Copy actual source code and build the application
COPY src ./src/
RUN touch src/main.rs && \
    cargo build --release

# ---- Runtime stage ----
FROM debian:bookworm-slim AS runtime
WORKDIR /app

# Install runtime dependencies (if needed)
RUN apt-get update && \
    apt-get install -y --no-install-recommends libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Create a non-root user to run the application
RUN useradd -ms /bin/bash appuser
USER appuser

# Copy the binary file from the build stage
COPY --from=build /app/target/release/portfolio-backend ./app

# Set the container startup command
CMD ["./app"]