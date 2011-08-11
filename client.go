package main

import(
	"fmt"
	"net"
	"os"
	"bufio"
	"crypto/rsa"
	"crypto/rand"
	"crypto/sha1"
	"strconv"
)

const(
	tcpProtocol	= "tcp4"
	keySize = 1024
	readWriterSize = keySize/8
)

func checkErr(err os.Error){
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

var	connectAddr = &net.TCPAddr{IP: net.IPv4(192,168,0,2), Port: 0}

func connectTo() *net.TCPConn{
	fmt.Print("Enter port:")
	fmt.Scanf("%d", &connectAddr.Port)
	fmt.Println("Connect to", connectAddr)
	c ,err := net.DialTCP(tcpProtocol, nil, connectAddr); checkErr(err)
	return c
}

func sendKey(c *net.TCPConn, k *rsa.PrivateKey) {
	c.Write([]byte("CONNECT\n"))
	c.Write([]byte(k.PublicKey.N.String() + "\n"))
	c.Write([]byte(strconv.Itoa(k.PublicKey.E) + "\n"))
}

func getBytes(buf *bufio.Reader, n int) []byte {
	bytes, err:= buf.Peek(n); checkErr(err)
	skipBytes(buf, n)
	return bytes
}

func skipBytes(buf *bufio.Reader, skipCount int){
	for i:=0; i<skipCount; i++ {
		buf.ReadByte()
	}
}

func main() {
	c := connectTo()
	buf := bufio.NewReader(c)
	k, err := rsa.GenerateKey(rand.Reader, keySize); checkErr(err)
	sendKey(c, k)

	for {
		cryptMsg := getBytes(buf, readWriterSize)
		msg, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, k, cryptMsg, nil)
		checkErr(err)
		fmt.Println(string(msg))
	}
}
