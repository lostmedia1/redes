FROM ubuntu:22.04
USER root

ENV DEBIAN_FRONTEND=noninteractive 

RUN apt-get update && apt-get install -y \
    dbus \
    python3 \
    python3-pip \
    libnm-dev \
    libpq-dev \
    python3-dev \
    gcc \
    wireless-tools \
    wireshark-common \
    tshark \
    sudo\
    iptables\
    && apt-get clean

WORKDIR /app


COPY requirements.txt /app/

RUN pip install --no-cache-dir -r requirements.txt
COPY . /app

EXPOSE 12345 12346
CMD ["python3", "/app/CrearHotspot.py"]

