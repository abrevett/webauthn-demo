# We are using an alpine build to reduce the image size
FROM python:alpine
WORKDIR /app
# Now Installing the required packages for app.py
COPY requirements.txt requirements.txt
## this line is just for webauthn to install
RUN apk add build-base libffi-dev
RUN pip3 install --trusted-host pypi.python.org -r requirements.txt
EXPOSE 8080
# Copying over only the files needed for the app itself
COPY static/ static/
COPY templates/ templates/
COPY app.py app.py
CMD ["python","app.py"]
