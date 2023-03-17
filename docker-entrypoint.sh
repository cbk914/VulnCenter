#!/bin/bash

# Wait for Redis to start
until redis-cli ping &>/dev/null; do
    sleep 1
done

# Start the script
getsploit "$@"
