package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/mistletoChao/dns"
)

const (
	defkey    = "mysm3"
	defsecret = "u2u/ug1uN3xR0y65LB8DSzLlG07sHUhKU05NTb25qz8="
)

var (
	localIP   string
	ip        string
	port      int
	zone      string
	keyName   string
	alg       string
	keySecret string
	algs      = []string{dns.HmacMD5, dns.HmacSHA1, dns.HmacSHA256, dns.HmacSHA512, dns.HmacSM3}
)

func init() {
	flag.StringVar(&zone, "z", ".", "zone name")
	flag.StringVar(&ip, "s", "", "dns server ip")
	flag.IntVar(&port, "p", 53, "dns server port")
	flag.StringVar(&localIP, "l", "", "local IP")
	flag.StringVar(&keyName, "k", "", "key name")
	flag.StringVar(&keySecret, "m", "", "key secret")
	flag.StringVar(&alg, "a", "hmac-sm3.", "key algorithm")
}

func main() {
	flag.Parse()
	if ip == "" {
		fmt.Printf("-s must be specified\n")
		os.Exit(1)
	}
	if keyName != "" || keySecret != "" {
		if keyName == "" || keySecret == "" {
			fmt.Printf("-k/-m must both be specified together\n")
			os.Exit(1)
		}

		if alg != dns.HmacMD5 && alg != dns.HmacSHA1 && alg != dns.HmacSHA256 &&
			alg != dns.HmacSHA512 && alg != dns.HmacSM3 {
			fmt.Printf("-a invalid\n")
			os.Exit(1)
		}
	}
	now := time.Now()
	m := new(dns.Msg)
	zone = dns.Fqdn(zone)
	m.SetAxfr(zone)
	tr := new(dns.Transfer)
	if keyName != "" && keySecret != "" {
		keyName = dns.Fqdn(keyName)
		tr.TsigSecret = map[string]string{
			keyName: keySecret,
		}
		m.SetTsig(keyName, alg, 300, time.Now().Unix())
	}

	var a chan *dns.Envelope
	var err error

	remoteAddr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	if localIP != "" {
		var addr net.Addr
		localStr := fmt.Sprintf("%s:0", localIP)
		addr, err = net.ResolveTCPAddr("tcp", localStr)
		if err != nil {
			fmt.Printf("resolve tcp failed:%s\n", err.Error())
			os.Exit(1)
		}

		dialer := &net.Dialer{
			LocalAddr: addr,
			Timeout:   5 * time.Second,
		}
		conn := new(dns.Conn)
		conn.Conn, err = dialer.Dial("tcp", remoteAddr)
		if err != nil {
			fmt.Printf("dial remote addr failed:%s\n", err.Error())
			os.Exit(1)
		}
		tr.Conn = conn
	}
	a, err = tr.In(m, remoteAddr)
	if err != nil {
		fmt.Printf("transfer in failed:%s\n", err.Error())
		os.Exit(1)
	}

	cnt := 0
	for ex := range a {
		if ex.Error != nil {
			fmt.Printf("%d package transfer failed:%s\n", cnt, ex.Error.Error())
			os.Exit(1)
		}
		fmt.Printf("========================= %d packages ==========================\n", cnt)
		for _, rr := range ex.RR {
			fmt.Printf("%s\n", rr.String())
		}
		cnt++
	}
	fmt.Printf("##################### axfr finished(%d packages && use:%v)\n", cnt, time.Now().Sub(now))
}
