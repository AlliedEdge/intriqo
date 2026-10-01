FROM ubuntu:22.04

# Victim container simulating various services
# Configured via environment variables

RUN apt-get update && apt-get install -y \
    openssh-server \
    apache2 \
    netcat-openbsd \
    tcpdump \
    python3 \
    python3-pip \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Configure SSH
RUN mkdir /var/run/sshd
RUN echo 'root:testpassword' | chpasswd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# Create test user
RUN useradd -m -s /bin/bash testuser && echo 'testuser:testpass' | chpasswd

# Setup simple web service
RUN echo '<html><body><h1>Test Service</h1></body></html>' > /var/www/html/index.html

# Create startup script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22 80 443 3306 5432 8000 8080 8443

ENTRYPOINT ["/entrypoint.sh"]
CMD ["tail", "-f", "/dev/null"]
