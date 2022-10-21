# syntax=docker/dockerfile:1

FROM golang:1.19.2

WORKDIR /app

COPY . .

RUN go install -v
RUN go build main.go
CMD ["go","run","."]

