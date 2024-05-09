FROM python:3-alpine

WORKDIR /app

COPY src/main.py ./

EXPOSE 514

CMD [ "python3", "-u", "./main.py" ]