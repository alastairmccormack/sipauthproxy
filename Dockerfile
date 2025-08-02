FROM python:3.13

RUN apt-get update && apt-get install -y mitmproxy

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .

ENV ASTERISK_SERVER=asterisk:5060

EXPOSE 5060/udp

CMD mitmdump --mode reverse:udp://$ASTERISK_SERVER --listen-port 5060 -s sipauthproxy.py