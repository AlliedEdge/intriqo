#!/bin/bash

# Start services based on SERVICE_TYPE environment variable

SERVICE_TYPE=${SERVICE_TYPE:-generic}

echo "Starting victim container: $SERVICE_TYPE"

# Always start SSH
service ssh start

# Start services based on type
case "$SERVICE_TYPE" in
    web)
        echo "Starting web services..."
        service apache2 start
        # Start simple Python HTTP servers on additional ports
        python3 -m http.server 8080 > /dev/null 2>&1 &
        python3 -m http.server 8443 > /dev/null 2>&1 &
        ;;
    database)
        echo "Starting database service listeners..."
        # Simulate database ports with netcat listeners
        nc -l -p 3306 -k > /dev/null 2>&1 &  # MySQL
        nc -l -p 5432 -k > /dev/null 2>&1 &  # PostgreSQL
        nc -l -p 27017 -k > /dev/null 2>&1 & # MongoDB
        nc -l -p 6379 -k > /dev/null 2>&1 &  # Redis
        ;;
    ssh)
        echo "Starting SSH service..."
        # SSH already started above
        # Add additional SSH on alternate port
        /usr/sbin/sshd -p 2222 -D > /dev/null 2>&1 &
        ;;
    application)
        echo "Starting application services..."
        # Multiple application ports
        for port in 8000 8001 8002 8003 8004 8005; do
            python3 -m http.server $port > /dev/null 2>&1 &
        done
        ;;
    *)
        echo "Generic victim - SSH only"
        ;;
esac

echo "Services started. Ready for traffic."

# Execute the main command
exec "$@"
