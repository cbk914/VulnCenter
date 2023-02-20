FROM ubuntu:latest

# Install dependencies
RUN apt-get update && apt-get install -y redis-server python3 python3-pip

# Install Python dependencies
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install -r /tmp/requirements.txt

# Copy script and entrypoint
COPY getsploit.py /usr/local/bin/getsploit
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Set entrypoint
ENTRYPOINT ["docker-entrypoint.sh"]

# Set default command
CMD ["redis-server", "--daemonize", "yes"]