package main

import (
	"context"
	"flag"
	"log"

	"github.com/mitetenov/remnawave-dns-guard-agent/internal/xraydownload"
)

func main() {
	version := flag.String("version", "v26.3.27", "reviewed official Xray release")
	arch := flag.String("arch", "amd64", "only amd64 is supported")
	destination := flag.String("destination", "/out/xray", "output executable")
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatal("invalid downloader arguments")
	}
	if err := xraydownload.Download(context.Background(), *version, *arch, *destination, xraydownload.FetchHTTPS); err != nil {
		log.Fatal(err)
	}
}
