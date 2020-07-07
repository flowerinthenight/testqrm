FROM golang:1.14.4
COPY go.* /go/src/github.com/flowerinthenight/testqrm/
COPY *.go /go/src/github.com/flowerinthenight/testqrm/
COPY vendor/ /go/src/github.com/flowerinthenight/testqrm/vendor/
WORKDIR /go/src/github.com/flowerinthenight/testqrm/
RUN GO111MODULE=on GOFLAGS=-mod=vendor CGO_ENABLED=1 GOOS=linux go build -v -a -installsuffix cgo -o testqrm .

FROM ubuntu:20.04
WORKDIR /testqrm/
COPY --from=0 /go/src/github.com/flowerinthenight/testqrm .
ENTRYPOINT ["/testqrm/testqrm"]
CMD ["run", "--logtostderr"]
