# Use an official Python runtime as a parent image
FROM python:alpine

# Set the working directory in the container
WORKDIR /app

# Install any needed dependencies specified in requirements.txt
COPY requirements.txt /tmp
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Copy the current directory contents into the container at /app
COPY /app /app

RUN adduser -H -D -s /usr/sbin/nologin batman
USER batman

# Run app.py when the container launches
CMD ["python", "monitor.py", \
        "-d", "/data", \
        "--fresh-domain", "$FRESHDOMAIN" \
    ]