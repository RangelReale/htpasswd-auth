FROM golang:1.15.2-alpine AS build
ENV CGO_ENABLED 0
RUN apk add --no-cache git
RUN mkdir -p /tmp
WORKDIR /build
COPY . .
RUN go get -u github.com/revel/revel
RUN go get -u github.com/revel/cmd/revel
RUN revel package . -m prod
#RUN mkdir -p /install
WORKDIR /install
RUN tar xzvf /build/build.tar.gz

# Final stage
FROM alpine:3.12
EXPOSE 9000
WORKDIR /app

COPY --from=build /install /app

CMD [ "/app/run.sh" ]
