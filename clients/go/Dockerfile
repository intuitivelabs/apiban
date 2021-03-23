### BUILD ###
FROM golang:1.15-alpine AS build

# Really needed?
# Set necessary environmet variables needed for our image
ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

WORKDIR /src

# Copy and download dependencies using go mod
COPY go.mod .
COPY go.sum .
RUN go mod download 

# Copy the code into the container
COPY . /src

# app directory in apiban-ipsets
WORKDIR /src/apiban-ipsets

RUN go build -o /out/apiban-ipsets ./...

### PKG ###
FROM goreleaser/nfpm AS package
# app directory in apiban-ipsets

# copy local files required for packages (systemd service file, nfpm config, app config...)
COPY ./apiban-ipsets/ /src/apiban-ipsets/
# copy built binary from "build" stage
COPY --from=build /out/apiban-ipsets /src/apiban-ipsets/

# create rpm package using nfpm
WORKDIR /src/apiban-ipsets
RUN /nfpm pkg --config /src/apiban-ipsets/nfpm.yaml --packager rpm --target /tmp/

### EXPORT ###
# Copy the generated package (and then using --output of docker build get just this file)
FROM scratch AS bin
COPY --from=package /tmp/ .
