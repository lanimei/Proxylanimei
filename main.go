package main

import (
	"github.com/snail007/goproxy/services"
	"log"
	"os"
	"os/signal"
	"syscall"
)

const APP_VERSION = "4.7"

func main() {
	err := initConfig()
	if err != nil {
		log.Fatalf("err : %s", err)
	}
	if service != nil && service.S != nil {
		Clean(&service.S)
	} else {
		Clean(nil)
	}
}


//这里主要是讲解到信号的使用,这个非常关键,一定要时刻注意.
func Clean(s *services.Service) {
	signalChan := make(chan os.Signal, 1)
	cleanupDone := make(chan bool)
	signal.Notify(signalChan,
		os.Interrupt,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)
	go func() {
		for _ = range signalChan {
			log.Println("Received an interrupt, stopping services...")
			if s != nil && *s != nil {
				(*s).Clean()
			}
			if cmd != nil {
				log.Printf("clean process %d", cmd.Process.Pid)
				cmd.Process.Kill()
			}
			cleanupDone <- true
		}
	}()
	<-cleanupDone
}


