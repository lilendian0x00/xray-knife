#!/bin/bash

case "$1" in
  "macos")
    go build -tags="with_gvisor,with_quic,with_wireguard,with_ech,with_utls,with_clash_api,with_grpc" -ldflags='-s -w' -trimpath
    ;;
  "win")
    GOOS=windows GOARCH=amd64 go build -tags="with_gvisor,with_quic,with_wireguard,with_ech,with_utls,with_clash_api,with_grpc" -ldflags='-s -w' -trimpath
    ;;
  "linux")
    GOOS=linux GOARCH=amd64 go build -tags="with_gvisor,with_quic,with_wireguard,with_ech,with_utls,with_clash_api,with_grpc" -ldflags='-s -w' -trimpath
    ;;
  *)
    echo "You have failed to specify what to do correctly."
    exit 1
    ;;

esac
