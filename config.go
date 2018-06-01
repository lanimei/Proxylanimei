package main

import (
	"bufio"
	"crypto/sha1"
	"fmt"
	"github.com/snail007/goproxy/services"
	"github.com/snail007/goproxy/services/kcpcfg"
	"github.com/snail007/goproxy/utils"
	"log"
	"os"
	"os/exec"
	"time"

	kcp "github.com/xtaci/kcp-go"
	"golang.org/x/crypto/pbkdf2"
	kingpin "gopkg.in/alecthomas/kingpin.v2"   //轻松帮助解析命令行参数信息
	"github.com/akkuman/parseConfig"
)

var (
	app     *kingpin.Application
	service *services.ServiceItem
	cmd     *exec.Cmd
)

func initConfig() (err error) {
	//keygen
	if len(os.Args) > 1 {
		if os.Args[1] == "keygen" {
			utils.Keygen()
			os.Exit(0)
		}
	}

	//define  args structs
	tunnelServerArgs := services.TunnelServerArgs{}  //定义上需要处理的结构体
	tunnelClientArgs := services.TunnelClientArgs{}
	tunnelBridgeArgs := services.TunnelBridgeArgs{}
	muxServerArgs := services.MuxServerArgs{}
	muxClientArgs := services.MuxClientArgs{}
	muxBridgeArgs := services.MuxBridgeArgs{}
	kcpArgs := kcpcfg.KCPConfigArgs{}
	//build srvice args
	//参数是两方面的,一方面是使用诸如Server Client Bridge 这样的参数,另一方面,在这个参数之中还会带有 -abc等小参数
	app = kingpin.New("proxy", "happy with proxy")   //配置了可执行程序proxy的运行参数,这个在fabric中也使用过
	app.Author("lanimei").Version(APP_VERSION)
	debug := app.Flag("debug", "debug log output").Default("false").Bool()
	daemon := app.Flag("daemon", "run proxy in background").Default("false").Bool()
	forever := app.Flag("forever", "run proxy in forever,fail and retry").Default("false").Bool()
	logfile := app.Flag("log", "log file path").Default("").String()
	kcpArgs.Key = app.Flag("kcp-key", "pre-shared secret between client and server").Default("secrect").String()
	kcpArgs.Crypt = app.Flag("kcp-method", "encrypt/decrypt method, can be: aes, aes-128, aes-192, salsa20, blowfish, twofish, cast5, 3des, tea, xtea, xor, sm4, none").Default("aes").Enum("aes", "aes-128", "aes-192", "salsa20", "blowfish", "twofish", "cast5", "3des", "tea", "xtea", "xor", "sm4", "none")
	kcpArgs.Mode = app.Flag("kcp-mode", "profiles: fast3, fast2, fast, normal, manual").Default("fast").Enum("fast3", "fast2", "fast", "normal", "manual")
	kcpArgs.MTU = app.Flag("kcp-mtu", "set maximum transmission unit for UDP packets").Default("1350").Int()
	kcpArgs.SndWnd = app.Flag("kcp-sndwnd", "set send window size(num of packets)").Default("1024").Int()
	kcpArgs.RcvWnd = app.Flag("kcp-rcvwnd", "set receive window size(num of packets)").Default("1024").Int()
	kcpArgs.DataShard = app.Flag("kcp-ds", "set reed-solomon erasure coding - datashard").Default("10").Int()
	kcpArgs.ParityShard = app.Flag("kcp-ps", "set reed-solomon erasure coding - parityshard").Default("3").Int()
	kcpArgs.DSCP = app.Flag("kcp-dscp", "set DSCP(6bit)").Default("0").Int()
	kcpArgs.NoComp = app.Flag("kcp-nocomp", "disable compression").Default("false").Bool()
	kcpArgs.AckNodelay = app.Flag("kcp-acknodelay", "be carefull! flush ack immediately when a packet is received").Default("true").Bool()
	kcpArgs.NoDelay = app.Flag("kcp-nodelay", "be carefull!").Default("0").Int()
	kcpArgs.Interval = app.Flag("kcp-interval", "be carefull!").Default("50").Int()
	kcpArgs.Resend = app.Flag("kcp-resend", "be carefull!").Default("0").Int()
	kcpArgs.NoCongestion = app.Flag("kcp-nc", "be carefull! no congestion").Default("0").Int()
	kcpArgs.SockBuf = app.Flag("kcp-sockbuf", "be carefull!").Default("4194304").Int()
	kcpArgs.KeepAlive = app.Flag("kcp-keepalive", "be carefull!").Default("10").Int()


	//########mux-server#########
	muxServer := app.Command("server", "proxy on mux server mode")
	muxServerArgs.Parent = muxServer.Flag("parent", "parent address, such as: \"23.32.32.19:28008\"").Default("").Short('P').String()
	muxServerArgs.ParentType = muxServer.Flag("parent-type", "parent protocol type <tls|tcp|kcp>").Default("tls").Short('T').Enum("tls", "tcp", "kcp")
	muxServerArgs.CertFile = muxServer.Flag("cert", "cert file for tls").Short('C').Default("proxy.crt").String()
	muxServerArgs.KeyFile = muxServer.Flag("key", "key file for tls").Short('K').Default("proxy.key").String()
	muxServerArgs.Timeout = muxServer.Flag("timeout", "tcp timeout with milliseconds").Short('i').Default("2000").Int()
	muxServerArgs.IsUDP = muxServer.Flag("udp", "proxy on udp mux server mode").Default("false").Bool()
	muxServerArgs.Key = muxServer.Flag("k", "client key").Default("default").String()
	muxServerArgs.Route = muxServer.Flag("route", "local route to client's network, such as: PROTOCOL://LOCAL_IP:LOCAL_PORT@[CLIENT_KEY]CLIENT_LOCAL_HOST:CLIENT_LOCAL_PORT").Short('r').Default("").Strings()
	muxServerArgs.IsCompress = muxServer.Flag("c", "compress data when tcp|tls mode").Default("false").Bool()
	muxServerArgs.SessionCount = muxServer.Flag("session-count", "session count which connect to bridge").Short('n').Default("10").Int()

	//########mux-client#########
	muxClient := app.Command("client", "proxy on mux client mode")
	muxClientArgs.Parent = muxClient.Flag("parent", "parent address, such as: \"23.32.32.19:28008\"").Default("").Short('P').String()
	muxClientArgs.ParentType = muxClient.Flag("parent-type", "parent protocol type <tls|tcp|kcp>").Default("tls").Short('T').Enum("tls", "tcp", "kcp")
	muxClientArgs.CertFile = muxClient.Flag("cert", "cert file for tls").Short('C').Default("proxy.crt").String()
	muxClientArgs.KeyFile = muxClient.Flag("key", "key file for tls").Short('K').Default("proxy.key").String()
	muxClientArgs.Timeout = muxClient.Flag("timeout", "tcp timeout with milliseconds").Short('i').Default("2000").Int()
	muxClientArgs.Key = muxClient.Flag("k", "key same with server").Default("default").String()
	muxClientArgs.IsCompress = muxClient.Flag("c", "compress data when tcp|tls mode").Default("false").Bool()
	muxClientArgs.SessionCount = muxClient.Flag("session-count", "session count which connect to bridge").Short('n').Default("10").Int()

	//########mux-bridge#########
	muxBridge := app.Command("bridge", "proxy on mux bridge mode")
	muxBridgeArgs.CertFile = muxBridge.Flag("cert", "cert file for tls").Short('C').Default("proxy.crt").String()
	muxBridgeArgs.KeyFile = muxBridge.Flag("key", "key file for tls").Short('K').Default("proxy.key").String()
	muxBridgeArgs.Timeout = muxBridge.Flag("timeout", "tcp timeout with milliseconds").Short('i').Default("2000").Int()
	muxBridgeArgs.Local = muxBridge.Flag("local", "local ip:port to listen").Short('p').Default(":33080").String()
	muxBridgeArgs.LocalType = muxBridge.Flag("local-type", "local protocol type <tls|tcp|kcp>").Default("tls").Short('t').Enum("tls", "tcp", "kcp")

	//########tunnel-server#########
	tunnelServer := app.Command("tserver", "proxy on tunnel server mode")
	tunnelServerArgs.Parent = tunnelServer.Flag("parent", "parent address, such as: \"23.32.32.19:28008\"").Default("").Short('P').String()
	tunnelServerArgs.CertFile = tunnelServer.Flag("cert", "cert file for tls").Short('C').Default("proxy.crt").String()
	tunnelServerArgs.KeyFile = tunnelServer.Flag("key", "key file for tls").Short('K').Default("proxy.key").String()
	tunnelServerArgs.Timeout = tunnelServer.Flag("timeout", "tcp timeout with milliseconds").Short('t').Default("2000").Int()
	tunnelServerArgs.IsUDP = tunnelServer.Flag("udp", "proxy on udp tunnel server mode").Default("false").Bool()
	tunnelServerArgs.Key = tunnelServer.Flag("k", "client key").Default("default").String()
	tunnelServerArgs.Route = tunnelServer.Flag("route", "local route to client's network, such as: PROTOCOL://LOCAL_IP:LOCAL_PORT@[CLIENT_KEY]CLIENT_LOCAL_HOST:CLIENT_LOCAL_PORT").Short('r').Default("").Strings()

	//########tunnel-client#########
	tunnelClient := app.Command("tclient", "proxy on tunnel client mode")
	tunnelClientArgs.Parent = tunnelClient.Flag("parent", "parent address, such as: \"23.32.32.19:28008\"").Default("").Short('P').String()
	tunnelClientArgs.CertFile = tunnelClient.Flag("cert", "cert file for tls").Short('C').Default("proxy.crt").String()
	tunnelClientArgs.KeyFile = tunnelClient.Flag("key", "key file for tls").Short('K').Default("proxy.key").String()
	tunnelClientArgs.Timeout = tunnelClient.Flag("timeout", "tcp timeout with milliseconds").Short('t').Default("2000").Int()
	tunnelClientArgs.Key = tunnelClient.Flag("k", "key same with server").Default("default").String()

	//########tunnel-bridge#########
	tunnelBridge := app.Command("tbridge", "proxy on tunnel bridge mode")
	tunnelBridgeArgs.CertFile = tunnelBridge.Flag("cert", "cert file for tls").Short('C').Default("proxy.crt").String()
	tunnelBridgeArgs.KeyFile = tunnelBridge.Flag("key", "key file for tls").Short('K').Default("proxy.key").String()
	tunnelBridgeArgs.Timeout = tunnelBridge.Flag("timeout", "tcp timeout with milliseconds").Short('t').Default("2000").Int()
	tunnelBridgeArgs.Local = tunnelBridge.Flag("local", "local ip:port to listen").Short('p').Default(":33080").String()

	//parse args
	serviceName := kingpin.MustParse(app.Parse(os.Args[1:]))

	//set kcp config

	switch *kcpArgs.Mode {
	case "normal":
		*kcpArgs.NoDelay, *kcpArgs.Interval, *kcpArgs.Resend, *kcpArgs.NoCongestion = 0, 40, 2, 1
	case "fast":
		*kcpArgs.NoDelay, *kcpArgs.Interval, *kcpArgs.Resend, *kcpArgs.NoCongestion = 0, 30, 2, 1
	case "fast2":
		*kcpArgs.NoDelay, *kcpArgs.Interval, *kcpArgs.Resend, *kcpArgs.NoCongestion = 1, 20, 2, 1
	case "fast3":
		*kcpArgs.NoDelay, *kcpArgs.Interval, *kcpArgs.Resend, *kcpArgs.NoCongestion = 1, 10, 2, 1
	}
	pass := pbkdf2.Key([]byte(*kcpArgs.Key), []byte("snail007-goproxy"), 4096, 32, sha1.New)

	switch *kcpArgs.Crypt {
	case "sm4":
		kcpArgs.Block, _ = kcp.NewSM4BlockCrypt(pass[:16])
	case "tea":
		kcpArgs.Block, _ = kcp.NewTEABlockCrypt(pass[:16])
	case "xor":
		kcpArgs.Block, _ = kcp.NewSimpleXORBlockCrypt(pass)
	case "none":
		kcpArgs.Block, _ = kcp.NewNoneBlockCrypt(pass)
	case "aes-128":
		kcpArgs.Block, _ = kcp.NewAESBlockCrypt(pass[:16])
	case "aes-192":
		kcpArgs.Block, _ = kcp.NewAESBlockCrypt(pass[:24])
	case "blowfish":
		kcpArgs.Block, _ = kcp.NewBlowfishBlockCrypt(pass)
	case "twofish":
		kcpArgs.Block, _ = kcp.NewTwofishBlockCrypt(pass)
	case "cast5":
		kcpArgs.Block, _ = kcp.NewCast5BlockCrypt(pass[:16])
	case "3des":
		kcpArgs.Block, _ = kcp.NewTripleDESBlockCrypt(pass[:24])
	case "xtea":
		kcpArgs.Block, _ = kcp.NewXTEABlockCrypt(pass[:16])
	case "salsa20":
		kcpArgs.Block, _ = kcp.NewSalsa20BlockCrypt(pass)
	default:
		*kcpArgs.Crypt = "aes"
		kcpArgs.Block, _ = kcp.NewAESBlockCrypt(pass)
	}
	//attach kcp config
	muxBridgeArgs.KCP = kcpArgs
	muxServerArgs.KCP = kcpArgs
	muxClientArgs.KCP = kcpArgs

	flags := log.Ldate
	if *debug {
		flags |= log.Lshortfile | log.Lmicroseconds
	} else {
		flags |= log.Ltime
	}
	log.SetFlags(flags)

	if *logfile != "" {
		f, e := os.OpenFile(*logfile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if e != nil {
			log.Fatal(e)
		}
		log.SetOutput(f)
	}
	if *daemon {
		args := []string{}
		for _, arg := range os.Args[1:] {
			if arg != "--daemon" {
				args = append(args, arg)
			}
		}
		cmd = exec.Command(os.Args[0], args...)
		cmd.Start()
		f := ""
		if *forever {
			f = "forever "
		}
		log.Printf("%s%s [PID] %d running...\n", f, os.Args[0], cmd.Process.Pid)
		os.Exit(0)
	}
	if *forever {
		args := []string{}
		for _, arg := range os.Args[1:] {
			if arg != "--forever" {
				args = append(args, arg)
			}
		}
		go func() {
			for {
				if cmd != nil {
					cmd.Process.Kill()
				}
				cmd = exec.Command(os.Args[0], args...)
				cmdReaderStderr, err := cmd.StderrPipe()
				if err != nil {
					log.Printf("ERR:%s,restarting...\n", err)
					continue
				}
				cmdReader, err := cmd.StdoutPipe()
				if err != nil {
					log.Printf("ERR:%s,restarting...\n", err)
					continue
				}
				scanner := bufio.NewScanner(cmdReader)
				scannerStdErr := bufio.NewScanner(cmdReaderStderr)
				go func() {
					for scanner.Scan() {
						fmt.Println(scanner.Text())
					}
				}()
				go func() {
					for scannerStdErr.Scan() {
						fmt.Println(scannerStdErr.Text())
					}
				}()
				if err := cmd.Start(); err != nil {
					log.Printf("ERR:%s,restarting...\n", err)
					continue
				}
				pid := cmd.Process.Pid
				log.Printf("worker %s [PID] %d running...\n", os.Args[0], pid)
				if err := cmd.Wait(); err != nil {
					log.Printf("ERR:%s,restarting...", err)
					continue
				}
				log.Printf("worker %s [PID] %d unexpected exited, restarting...\n", os.Args[0], pid)
				time.Sleep(time.Second * 5)
			}
		}()
		return
	}
	if *logfile == "" {
		poster()
	}
	//扩展参数的相关问题
	var config = parseConfig.New("config2.json")
	var bridge_localport = config.Get("bridge_localport")
	bridge_localport_string := bridge_localport.(string)
	var server_route = config.Get("server_route")
	server_route_string := server_route.(string)
	var server_route_strings []string
	server_route_strings = append(server_route_strings, server_route_string)
	var server_parent = config.Get("server_route")
	server_parent_string := server_parent.(string)
	if bridge_localport_string != ""{
		*(muxBridgeArgs.Local) = bridge_localport_string
		*(tunnelBridgeArgs.Local) = bridge_localport_string
	}
	if server_route_string != ""{
		*(muxServerArgs.Route) = server_route_strings
		*(tunnelServerArgs.Route) =server_route_strings
	}
	if server_parent_string != ""{
		*(muxServerArgs.Parent) = server_parent_string
		*(tunnelServerArgs.Parent) = server_parent_string
	}
	//regist services and run service
	log.Println(*(muxBridgeArgs.Local))
	log.Println(*(muxServerArgs.Route))
	log.Println(*(muxServerArgs.Parent))
	services.Regist("tserver", services.NewTunnelServerManager(), tunnelServerArgs)
	services.Regist("tclient", services.NewTunnelClient(), tunnelClientArgs)
	services.Regist("tbridge", services.NewTunnelBridge(), tunnelBridgeArgs)
	services.Regist("server", services.NewMuxServerManager(), muxServerArgs)
	services.Regist("client", services.NewMuxClient(), muxClientArgs)
	services.Regist("bridge", services.NewMuxBridge(), muxBridgeArgs)
	service, err = services.Run(serviceName)
	if err != nil {
		log.Fatalf("run service [%s] fail, ERR:%s", serviceName, err)
	}
	return
}

func poster() {
	fmt.Printf(`
		########  ########   #######  ##     ## ##    ## 
		##     ## ##     ## ##     ##  ##   ##   ##  ##  
		##     ## ##     ## ##     ##   ## ##     ####   
		########  ########  ##     ##    ###       ##    
		##        ##   ##   ##     ##   ## ##      ##    
		##        ##    ##  ##     ##  ##   ##     ##    
		##        ##     ##  #######  ##     ##    ##    
		
		v%s`+" by snail , blog : http://www.host900.com/\n\n", APP_VERSION)
}
