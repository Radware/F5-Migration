
FROM alpine:latest

RUN apk add --no-cache python3 && \
	apk add --no-cache python3-dev && \
    python3 -m ensurepip && \
    rm -r /usr/lib/python*/ensurepip && \
    pip3 install --upgrade pip setuptools && \
    rm -r /root/.cache

COPY . /app
WORKDIR /app

expose 3011
RUN pip install -U Flask

ENV FLASK_APP=browse.py

CMD ["python3", "-m", "flask", "run", "--host=0.0.0.0", "-p 3011"] 
