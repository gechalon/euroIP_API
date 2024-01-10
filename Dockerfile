FROM python:3.8-slim-buster

WORKDIR /app
COPY bbdd /app/bbdd
COPY listas /app/listas

#ENV PYTHONBUFFERED True
#ENV SQLITE_URL sqlite:////app/bbdd/test.db
ENV SQLITE_URL sqlite:////app/bbdd/privacyIPusers.db
ENV DB_PATH /app/bbdd/
ENV listas_PATH /app/listas/
ENV DATABASE_URL /app/bbdd/
ENV PRODUCTION  True
ENV PORT 8080
ENV FLASK_ENV production
#ENV FLASK_ENV CLOUDSERVER
#ENV CLOUDSERVER True
ENV PYTHONIOENCODING=utf-8
ENV LC_ALL en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US.UTF-8

COPY requirements.txt requirements.txt

RUN pip3 install --no-cache-dir -r requirements.txt

COPY . .

CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 0 --env LANG=en_US.utf-8 wsgi:app