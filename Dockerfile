# FROM golang:alpine AS builder

# RUN apk update && apk add --no-cache git tzdata
# RUN apk add ca-certificates && update-ca-certificates

# WORKDIR $GOPATH/src/authorizer/

# COPY go.mod .

# RUN go mod download
# RUN go mod verify

# COPY . .

# RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -tags netgo -ldflags '-w' -o /go/bin/authorizer cmd/authorizer/*.go


# FROM ubuntu:latest

# COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
# COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
# COPY --from=builder /go/bin/authorizer /go/bin/authorizer

# WORKDIR /go/bin/

# COPY ./entrypoint.sh .
# COPY ./scope_to_rules.json .

# RUN apt-get update
# RUN apt-get install -y jq

# RUN chmod +x entrypoint.sh

FROM ubuntu:latest

RUN apt-get update && apt-get install -y \
        software-properties-common
RUN add-apt-repository ppa:deadsnakes/ppa
RUN apt-get update && apt-get install -y \
    python3.7 \
    python3-pip
RUN python3.7 -m pip install pip
RUN apt-get update && apt-get install -y \
    python3-distutils \
    python3-setuptools
RUN python3.7 -m pip install pip --upgrade pip

RUN pip3 install jwt
RUN pip3 install re
RUN pip3 install jsonpath_ng
RUN pip3 install urllib3

COPY . /app/

WORKDIR /app

CMD [ "python3", "./test.py"]