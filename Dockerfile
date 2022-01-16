FROM golang:1.16

WORKDIR /src

COPY . .
RUN go build -o /bin/402 .

ENTRYPOINT [ "/bin/402" ]