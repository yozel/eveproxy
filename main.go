package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/jessevdk/go-flags"
)

var (
	dAddr string
)

var opts struct {
	ListenAddr      string `short:"l" long:"listen-address" required:"true" default:"127.0.0.1:8000" name:"Listen address"`
	ListenCert      string `short:"c" long:"listen-cert" required:"true" name:"Listen TLS server certificate"`
	ListenKey       string `short:"k" long:"listen-key" required:"true" name:"Listen TLS server key"`
	DestinationAddr string `short:"d" long:"destination-address" required:"true" name:"Destination address"`
	SSLKeyLogFile   string `short:"w" long:"sslkeylogfile" required:"true" name:"SSLKEYLOGFILE path" env:"SSLKEYLOGFILE"`
}

func main() {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		os.Exit(1)
	}()

	_, err := flags.Parse(&opts)
	if err != nil {
		os.Exit(1)
	}
	service := opts.ListenAddr

	cert, err := tls.LoadX509KeyPair(opts.ListenCert, opts.ListenKey)
	if err != nil {
		log.Fatalf("server: loadkeys: %s", err)
	}
	f, err := os.OpenFile(opts.SSLKeyLogFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	defer f.Close()

	config := tls.Config{Certificates: []tls.Certificate{cert}, KeyLogWriter: f}
	// service := "0.0.0.0:8000"
	listener, err := tls.Listen("tcp", service, &config)
	if err != nil {
		log.Fatalf("sConn listen %s error: %s", service, err)
	}
	log.Printf("sConn listening %s", service)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatalf("sConn accept error: %s", err)
			break
		}
		go handle(conn)
	}
}

func handle(sConn net.Conn) {
	defer sConn.Close()
	logPrefix := fmt.Sprintf("[%s]", sConn.RemoteAddr())
	log.Printf("%s sConn: accepted", logPrefix)

	dAddr := opts.DestinationAddr
	dConn, err := tls.Dial("tcp", dAddr, nil)
	if err != nil {
		log.Printf("%s dConn: can't dial: %s", logPrefix, err)
		return
	}
	defer dConn.Close()
	log.Printf("%s dConn: TLS handshake is ok", logPrefix)

	tlscon, ok := sConn.(*tls.Conn)

	if ok {
		err = tlscon.Handshake()
	}
	if !ok || err != nil {
		log.Printf("%s sConn: error: %s", logPrefix, err)
		return
	}
	log.Printf("%s sConn: TLS handshake is ok", logPrefix)

	//bidirectional pipe
	log.Printf("%s piping sConn <-> dConn", logPrefix)
	if err = pipe(sConn, dConn); err != nil {
		log.Printf("%s pipe error: %s", logPrefix, err)
	}
	log.Printf("%s pipe is done, connections are closed", logPrefix)
}

func pipe(sConn, dConn io.ReadWriteCloser) error {
	c := make(chan error)
	go func() {
		// sConn -> dConn
		_, err := io.Copy(dConn, sConn)
		c <- err
	}()

	go func() {
		// dConn -> sConn
		_, err := io.Copy(sConn, dConn)
		c <- err
	}()

	err := <-c
	sConn.Close()
	dConn.Close()
	return err
}
