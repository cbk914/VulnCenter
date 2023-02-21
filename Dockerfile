FROM ubuntu:latest

# Install dependencies
RUN apt-get update && apt-get install -y redis-server python3 python3-pip

# Install Python dependencies
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install -r /tmp/requirements.txt

# Copy scripts and entrypoint
COPY getsploit.py /usr/local/bin/getsploit
COPY get-nvdcve.py /usr/local/bin/get-nvdcve
COPY vulncenter.py /usr/local/bin/vulncenter
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/getsploit
RUN chmod +x /usr/local/bin/get-nvdcve
RUN chmod +x /usr/local/bin/vulncenter

# Set entrypoint
ENTRYPOINT ["docker-entrypoint.sh"]

# Set default command
CMD ["redis-server", "--daemonize", "yes"]
