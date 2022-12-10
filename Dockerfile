FROM golang:1.18 as builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o /bin/esmtpfa cmd/esmtpfa/*.go

FROM debian:bullseye-slim as runner

RUN apt-get update && apt-get install -y ca-certificates

COPY --from=builder /bin/esmtpfa /bin/esmtpfa

EXPOSE 25
EXPOSE 465
EXPOSE 8080
EXPOSE 9090

ENTRYPOINT ["/bin/esmtpfa"]