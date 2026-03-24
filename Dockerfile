# Use Ubuntu as the base image
FROM ubuntu:24.04

# Install necessary network tools
RUN apt-get update && apt-get install -y \
    iproute2 \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Copy the compiled binary
COPY target/release/transpar_nc /usr/local/bin/transpar_nc

# Set the working directory
WORKDIR /app

# Default command
CMD ["transpar_nc"]
