// tproxy.go - Complete TCP and UDP TPROXY implementation
package main

import (
	"encoding/gob"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	IP_TRANSPARENT     = 19
	IP_RECVORIGDSTADDR = 20
	SO_ORIGINAL_DST    = 80

	// UDP session timeout
	UDP_TIMEOUT = 30 * time.Second
)

// Protocol type
type Protocol uint8

const (
	ProtoTCP Protocol = iota
	ProtoUDP
)

// Message types
type MessageType uint8

const (
	MsgTypeNewConnection MessageType = iota
	MsgTypeData
	MsgTypeClose
)

// ConnectionInfo holds original connection metadata
type ConnectionInfo struct {
	Protocol        Protocol
	OriginalSrcIP   string
	OriginalSrcPort uint16
	OriginalDstIP   string
	OriginalDstPort uint16
	ConnectionID    uint64
}

// PacketData for transferring data
type PacketData struct {
	ConnectionID uint64
	Data         []byte
	IsClose      bool
}

// ProtocolMessage wraps all message types
type ProtocolMessage struct {
	Type       MessageType
	ConnInfo   *ConnectionInfo
	PacketData *PacketData
}

var connectionCounter uint64

func main() {
	mode := flag.String("mode", "client", "Run mode: 'client' or 'server'")
	socketPath := flag.String("socket", "/tmp/tproxy.sock", "Unix domain socket path")
	addr := flag.String("listen", "0.0.0.0:1088", "TPROXY TCP/UDP listen address (client mode)")
	flag.Parse()

	switch *mode {
	case "server":
		runServer(*socketPath)
	case "client":
		runClient(*addr, *addr, *socketPath)
	default:
		log.Fatalf("Unknown mode: %s", *mode)
	}
}

// ==================== CLIENT ====================

type Client struct {
	socketPath string
	encoder    *gob.Encoder
	decoder    *gob.Decoder
	unixConn   net.Conn
	mu         sync.Mutex

	// TCP connections
	tcpConnMap   map[uint64]net.Conn
	tcpConnMapMu sync.RWMutex

	// UDP sessions
	udpSessions   map[uint64]*UDPSession
	udpSessionsMu sync.RWMutex
	udpConn       *net.UDPConn
}

// UDPSession tracks a UDP "connection"
type UDPSession struct {
	clientAddr  *net.UDPAddr
	originalDst *net.UDPAddr
	lastActive  time.Time
	connID      uint64
}

func runClient(tcpListenAddr, udpListenAddr, socketPath string) {
	client := &Client{
		socketPath:  socketPath,
		tcpConnMap:  make(map[uint64]net.Conn),
		udpSessions: make(map[uint64]*UDPSession),
	}

	if err := client.connectToServer(); err != nil {
		log.Fatalf("Failed to connect to server: %v", err)
	}
	defer client.unixConn.Close()

	// Start response handler
	go client.handleResponses()

	// Start UDP session cleaner
	go client.cleanupUDPSessions()

	// Start TCP listener
	go client.runTCPListener(tcpListenAddr)

	// Start UDP listener (blocking)
	client.runUDPListener(udpListenAddr)
}

func (c *Client) connectToServer() error {
	conn, err := net.Dial("unix", c.socketPath)
	if err != nil {
		return err
	}
	c.unixConn = conn
	c.encoder = gob.NewEncoder(conn)
	c.decoder = gob.NewDecoder(conn)
	return nil
}

// ==================== TCP CLIENT ====================

func (c *Client) runTCPListener(addr string) {
	listener, err := createTPROXYTCPListener(addr)
	if err != nil {
		log.Fatalf("Failed to create TCP TPROXY listener: %v", err)
	}
	defer listener.Close()

	log.Printf("TCP TPROXY listening on %s", addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("TCP Accept error: %v", err)
			continue
		}
		go c.handleTCPConnection(conn)
	}
}

func createTPROXYTCPListener(addr string) (net.Listener, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}

	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, IP_TRANSPARENT, 1); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("IP_TRANSPARENT: %v (need CAP_NET_ADMIN)", err)
	}

	sa := &syscall.SockaddrInet4{Port: tcpAddr.Port}
	if tcpAddr.IP != nil && tcpAddr.IP.To4() != nil {
		copy(sa.Addr[:], tcpAddr.IP.To4())
	}

	if err := syscall.Bind(fd, sa); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	if err := syscall.Listen(fd, syscall.SOMAXCONN); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	file := os.NewFile(uintptr(fd), "tcp-tproxy")
	listener, err := net.FileListener(file)
	file.Close()
	return listener, err
}

func (c *Client) handleTCPConnection(conn net.Conn) {
	defer conn.Close()

	// For TPROXY, local address is the original destination
	localAddr := conn.LocalAddr().(*net.TCPAddr)
	remoteAddr := conn.RemoteAddr().(*net.TCPAddr)

	connID := atomic.AddUint64(&connectionCounter, 1)

	c.tcpConnMapMu.Lock()
	c.tcpConnMap[connID] = conn
	c.tcpConnMapMu.Unlock()

	connInfo := &ConnectionInfo{
		Protocol:        ProtoTCP,
		OriginalSrcIP:   remoteAddr.IP.String(),
		OriginalSrcPort: uint16(remoteAddr.Port),
		OriginalDstIP:   localAddr.IP.String(),
		OriginalDstPort: uint16(localAddr.Port),
		ConnectionID:    connID,
	}

	log.Printf("TCP [%d]: %s:%d -> %s:%d",
		connID, connInfo.OriginalSrcIP, connInfo.OriginalSrcPort,
		connInfo.OriginalDstIP, connInfo.OriginalDstPort)

	c.mu.Lock()
	err := c.encoder.Encode(&ProtocolMessage{Type: MsgTypeNewConnection, ConnInfo: connInfo})
	c.mu.Unlock()

	if err != nil {
		c.removeTCPConnection(connID)
		return
	}

	buf := make([]byte, 65536)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		c.mu.Lock()
		c.encoder.Encode(&ProtocolMessage{
			Type:       MsgTypeData,
			PacketData: &PacketData{ConnectionID: connID, Data: buf[:n]},
		})
		c.mu.Unlock()
	}

	c.mu.Lock()
	c.encoder.Encode(&ProtocolMessage{
		Type:       MsgTypeClose,
		PacketData: &PacketData{ConnectionID: connID, IsClose: true},
	})
	c.mu.Unlock()
	c.removeTCPConnection(connID)
}

func (c *Client) removeTCPConnection(connID uint64) {
	c.tcpConnMapMu.Lock()
	if conn, ok := c.tcpConnMap[connID]; ok {
		conn.Close()
		delete(c.tcpConnMap, connID)
	}
	c.tcpConnMapMu.Unlock()
}

// ==================== UDP CLIENT ====================

func (c *Client) runUDPListener(addr string) {
	conn, err := createTPROXYUDPListener(addr)
	if err != nil {
		log.Fatalf("Failed to create UDP TPROXY listener: %v", err)
	}
	defer conn.Close()

	c.udpConn = conn
	log.Printf("UDP TPROXY listening on %s", addr)

	buf := make([]byte, 65536)
	oob := make([]byte, 1024)

	for {
		n, oobn, _, srcAddr, err := conn.ReadMsgUDP(buf, oob)
		if err != nil {
			log.Printf("UDP read error: %v", err)
			continue
		}

		// Parse original destination from control message
		origDst, err := parseOriginalDstFromOOB(oob[:oobn])
		if err != nil {
			log.Printf("Failed to get original dst: %v", err)
			continue
		}

		c.handleUDPPacket(srcAddr, origDst, buf[:n])
	}
}

func createTPROXYUDPListener(addr string) (*net.UDPConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return nil, err
	}

	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	// Enable TPROXY
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, IP_TRANSPARENT, 1); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("IP_TRANSPARENT: %v (need CAP_NET_ADMIN)", err)
	}

	// Enable receiving original destination address
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, IP_RECVORIGDSTADDR, 1); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("IP_RECVORIGDSTADDR: %v", err)
	}

	sa := &syscall.SockaddrInet4{Port: udpAddr.Port}
	if udpAddr.IP != nil && udpAddr.IP.To4() != nil {
		copy(sa.Addr[:], udpAddr.IP.To4())
	}

	if err := syscall.Bind(fd, sa); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	file := os.NewFile(uintptr(fd), "udp-tproxy")
	fileConn, err := net.FileConn(file)
	file.Close()
	if err != nil {
		return nil, err
	}

	return fileConn.(*net.UDPConn), nil
}

func parseOriginalDstFromOOB(oob []byte) (*net.UDPAddr, error) {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, err
	}

	for _, msg := range msgs {
		if msg.Header.Level == syscall.IPPROTO_IP && msg.Header.Type == IP_RECVORIGDSTADDR {
			// struct sockaddr_in
			if len(msg.Data) < 8 {
				continue
			}
			port := uint16(msg.Data[2])<<8 + uint16(msg.Data[3])
			ip := net.IPv4(msg.Data[4], msg.Data[5], msg.Data[6], msg.Data[7])
			return &net.UDPAddr{IP: ip, Port: int(port)}, nil
		}
	}

	return nil, fmt.Errorf("original destination not found in OOB data")
}

func (c *Client) handleUDPPacket(srcAddr, dstAddr *net.UDPAddr, data []byte) {
	// Create session key
	sessionKey := fmt.Sprintf("%s-%s", srcAddr.String(), dstAddr.String())

	c.udpSessionsMu.Lock()
	var session *UDPSession
	var connID uint64
	var isNew bool

	// Find existing session
	for _, s := range c.udpSessions {
		if s.clientAddr.String() == srcAddr.String() &&
			s.originalDst.String() == dstAddr.String() {
			session = s
			connID = s.connID
			session.lastActive = time.Now()
			break
		}
	}

	if session == nil {
		// Create new session
		connID = atomic.AddUint64(&connectionCounter, 1)
		session = &UDPSession{
			clientAddr:  srcAddr,
			originalDst: dstAddr,
			lastActive:  time.Now(),
			connID:      connID,
		}
		c.udpSessions[connID] = session
		isNew = true
	}
	c.udpSessionsMu.Unlock()

	if isNew {
		connInfo := &ConnectionInfo{
			Protocol:        ProtoUDP,
			OriginalSrcIP:   srcAddr.IP.String(),
			OriginalSrcPort: uint16(srcAddr.Port),
			OriginalDstIP:   dstAddr.IP.String(),
			OriginalDstPort: uint16(dstAddr.Port),
			ConnectionID:    connID,
		}

		log.Printf("UDP [%d]: %s:%d -> %s:%d (session: %s)",
			connID, connInfo.OriginalSrcIP, connInfo.OriginalSrcPort,
			connInfo.OriginalDstIP, connInfo.OriginalDstPort, sessionKey)

		c.mu.Lock()
		c.encoder.Encode(&ProtocolMessage{Type: MsgTypeNewConnection, ConnInfo: connInfo})
		c.mu.Unlock()
	}

	// Send data
	c.mu.Lock()
	c.encoder.Encode(&ProtocolMessage{
		Type:       MsgTypeData,
		PacketData: &PacketData{ConnectionID: connID, Data: data},
	})
	c.mu.Unlock()
}

func (c *Client) cleanupUDPSessions() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		c.udpSessionsMu.Lock()
		for id, session := range c.udpSessions {
			if now.Sub(session.lastActive) > UDP_TIMEOUT {
				log.Printf("UDP session %d timed out", id)
				c.mu.Lock()
				c.encoder.Encode(&ProtocolMessage{
					Type:       MsgTypeClose,
					PacketData: &PacketData{ConnectionID: id, IsClose: true},
				})
				c.mu.Unlock()
				delete(c.udpSessions, id)
			}
		}
		c.udpSessionsMu.Unlock()
	}
}

// ==================== CLIENT RESPONSE HANDLER ====================

func (c *Client) handleResponses() {
	for {
		var msg ProtocolMessage
		if err := c.decoder.Decode(&msg); err != nil {
			if err != io.EOF {
				log.Printf("Decode error: %v", err)
			}
			return
		}

		switch msg.Type {
		case MsgTypeData:
			if msg.PacketData == nil {
				continue
			}
			connID := msg.PacketData.ConnectionID

			// Try TCP first
			c.tcpConnMapMu.RLock()
			tcpConn, isTCP := c.tcpConnMap[connID]
			c.tcpConnMapMu.RUnlock()

			if isTCP {
				tcpConn.Write(msg.PacketData.Data)
				continue
			}

			// Try UDP
			c.udpSessionsMu.RLock()
			session, isUDP := c.udpSessions[connID]
			c.udpSessionsMu.RUnlock()

			if isUDP {
				c.sendUDPResponse(session, msg.PacketData.Data)
			}

		case MsgTypeClose:
			if msg.PacketData == nil {
				continue
			}
			connID := msg.PacketData.ConnectionID

			// Try removing from TCP
			c.tcpConnMapMu.Lock()
			if conn, ok := c.tcpConnMap[connID]; ok {
				conn.Close()
				delete(c.tcpConnMap, connID)
			}
			c.tcpConnMapMu.Unlock()

			// Try removing from UDP
			c.udpSessionsMu.Lock()
			delete(c.udpSessions, connID)
			c.udpSessionsMu.Unlock()
		}
	}
}

func (c *Client) sendUDPResponse(session *UDPSession, data []byte) {
	// Create a socket that can send from the original destination address
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		log.Printf("Failed to create UDP response socket: %v", err)
		return
	}
	defer syscall.Close(fd)

	// Enable IP_TRANSPARENT to bind to non-local address
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, IP_TRANSPARENT, 1); err != nil {
		log.Printf("Failed to set IP_TRANSPARENT: %v", err)
		return
	}

	// Bind to the original destination address (spoofing source)
	srcSa := &syscall.SockaddrInet4{Port: int(session.originalDst.Port)}
	copy(srcSa.Addr[:], session.originalDst.IP.To4())

	if err := syscall.Bind(fd, srcSa); err != nil {
		log.Printf("Failed to bind UDP response socket: %v", err)
		return
	}

	// Send to the client
	dstSa := &syscall.SockaddrInet4{Port: session.clientAddr.Port}
	copy(dstSa.Addr[:], session.clientAddr.IP.To4())

	if err := syscall.Sendto(fd, data, 0, dstSa); err != nil {
		log.Printf("Failed to send UDP response: %v", err)
	}
}

// ==================== SERVER ====================

type Server struct {
	connections   map[uint64]*ProxyConnection
	connectionsMu sync.RWMutex
}

type ProxyConnection struct {
	info       *ConnectionInfo
	tcpConn    net.Conn     // For TCP
	udpConn    *net.UDPConn // For UDP
	targetAddr *net.UDPAddr // For UDP
	encoder    *gob.Encoder
	encoderMu  *sync.Mutex
}

func runServer(socketPath string) {
	os.Remove(socketPath)

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("Failed to create Unix socket: %v", err)
	}
	defer listener.Close()
	os.Chmod(socketPath, 0777)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		listener.Close()
		os.Remove(socketPath)
		os.Exit(0)
	}()

	log.Printf("Server listening on: %s", socketPath)

	server := &Server{connections: make(map[uint64]*ProxyConnection)}

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go server.handleClient(conn)
	}
}

func (s *Server) handleClient(conn net.Conn) {
	defer conn.Close()

	encoder := gob.NewEncoder(conn)
	decoder := gob.NewDecoder(conn)
	encoderMu := &sync.Mutex{}

	log.Printf("Client connected")

	for {
		var msg ProtocolMessage
		if err := decoder.Decode(&msg); err != nil {
			if err != io.EOF {
				log.Printf("Decode error: %v", err)
			}
			break
		}

		switch msg.Type {
		case MsgTypeNewConnection:
			if msg.ConnInfo != nil {
				if msg.ConnInfo.Protocol == ProtoTCP {
					s.handleNewTCPConnection(msg.ConnInfo, encoder, encoderMu)
				} else {
					s.handleNewUDPConnection(msg.ConnInfo, encoder, encoderMu)
				}
			}
		case MsgTypeData:
			if msg.PacketData != nil {
				s.handleData(msg.PacketData)
			}
		case MsgTypeClose:
			if msg.PacketData != nil {
				s.handleClose(msg.PacketData.ConnectionID)
			}
		}
	}
	s.cleanupConnections()
}

func (s *Server) handleNewTCPConnection(info *ConnectionInfo, encoder *gob.Encoder, encoderMu *sync.Mutex) {
	log.Printf("TCP Proxy [%d]: %s:%d -> %s:%d",
		info.ConnectionID, info.OriginalSrcIP, info.OriginalSrcPort,
		info.OriginalDstIP, info.OriginalDstPort)

	targetAddr := fmt.Sprintf("%s:%d", info.OriginalDstIP, info.OriginalDstPort)
	targetConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		log.Printf("Failed to connect to %s: %v", targetAddr, err)
		encoderMu.Lock()
		encoder.Encode(&ProtocolMessage{
			Type:       MsgTypeClose,
			PacketData: &PacketData{ConnectionID: info.ConnectionID, IsClose: true},
		})
		encoderMu.Unlock()
		return
	}

	pc := &ProxyConnection{
		info:      info,
		tcpConn:   targetConn,
		encoder:   encoder,
		encoderMu: encoderMu,
	}

	s.connectionsMu.Lock()
	s.connections[info.ConnectionID] = pc
	s.connectionsMu.Unlock()

	go s.readFromTCPTarget(pc)
}

func (s *Server) handleNewUDPConnection(info *ConnectionInfo, encoder *gob.Encoder, encoderMu *sync.Mutex) {
	log.Printf("UDP Proxy [%d]: %s:%d -> %s:%d",
		info.ConnectionID, info.OriginalSrcIP, info.OriginalSrcPort,
		info.OriginalDstIP, info.OriginalDstPort)

	targetAddr, err := net.ResolveUDPAddr("udp",
		fmt.Sprintf("%s:%d", info.OriginalDstIP, info.OriginalDstPort))
	if err != nil {
		log.Printf("Failed to resolve UDP address: %v", err)
		return
	}

	udpConn, err := net.DialUDP("udp", nil, targetAddr)
	if err != nil {
		log.Printf("Failed to create UDP connection: %v", err)
		encoderMu.Lock()
		encoder.Encode(&ProtocolMessage{
			Type:       MsgTypeClose,
			PacketData: &PacketData{ConnectionID: info.ConnectionID, IsClose: true},
		})
		encoderMu.Unlock()
		return
	}

	pc := &ProxyConnection{
		info:       info,
		udpConn:    udpConn,
		targetAddr: targetAddr,
		encoder:    encoder,
		encoderMu:  encoderMu,
	}

	s.connectionsMu.Lock()
	s.connections[info.ConnectionID] = pc
	s.connectionsMu.Unlock()

	go s.readFromUDPTarget(pc)
}

func (s *Server) readFromTCPTarget(pc *ProxyConnection) {
	buf := make([]byte, 65536)
	for {
		n, err := pc.tcpConn.Read(buf)
		if err != nil {
			break
		}
		pc.encoderMu.Lock()
		pc.encoder.Encode(&ProtocolMessage{
			Type:       MsgTypeData,
			PacketData: &PacketData{ConnectionID: pc.info.ConnectionID, Data: buf[:n]},
		})
		pc.encoderMu.Unlock()
	}

	pc.encoderMu.Lock()
	pc.encoder.Encode(&ProtocolMessage{
		Type:       MsgTypeClose,
		PacketData: &PacketData{ConnectionID: pc.info.ConnectionID, IsClose: true},
	})
	pc.encoderMu.Unlock()
	s.handleClose(pc.info.ConnectionID)
}

func (s *Server) readFromUDPTarget(pc *ProxyConnection) {
	buf := make([]byte, 65536)
	pc.udpConn.SetReadDeadline(time.Now().Add(UDP_TIMEOUT))

	for {
		n, err := pc.udpConn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				log.Printf("UDP connection %d timed out", pc.info.ConnectionID)
			}
			break
		}

		// Reset deadline on activity
		pc.udpConn.SetReadDeadline(time.Now().Add(UDP_TIMEOUT))

		pc.encoderMu.Lock()
		pc.encoder.Encode(&ProtocolMessage{
			Type:       MsgTypeData,
			PacketData: &PacketData{ConnectionID: pc.info.ConnectionID, Data: buf[:n]},
		})
		pc.encoderMu.Unlock()
	}

	pc.encoderMu.Lock()
	pc.encoder.Encode(&ProtocolMessage{
		Type:       MsgTypeClose,
		PacketData: &PacketData{ConnectionID: pc.info.ConnectionID, IsClose: true},
	})
	pc.encoderMu.Unlock()
	s.handleClose(pc.info.ConnectionID)
}

func (s *Server) handleData(data *PacketData) {
	s.connectionsMu.RLock()
	pc, ok := s.connections[data.ConnectionID]
	s.connectionsMu.RUnlock()

	if !ok {
		return
	}

	if pc.info.Protocol == ProtoTCP {
		if pc.tcpConn != nil {
			pc.tcpConn.Write(data.Data)
		}
	} else {
		if pc.udpConn != nil {
			pc.udpConn.Write(data.Data)
		}
	}
}

func (s *Server) handleClose(connID uint64) {
	s.connectionsMu.Lock()
	if pc, ok := s.connections[connID]; ok {
		if pc.tcpConn != nil {
			pc.tcpConn.Close()
		}
		if pc.udpConn != nil {
			pc.udpConn.Close()
		}
		delete(s.connections, connID)
		log.Printf("Connection %d closed", connID)
	}
	s.connectionsMu.Unlock()
}

func (s *Server) cleanupConnections() {
	s.connectionsMu.Lock()
	for id, pc := range s.connections {
		if pc.tcpConn != nil {
			pc.tcpConn.Close()
		}
		if pc.udpConn != nil {
			pc.udpConn.Close()
		}
		delete(s.connections, id)
	}
	s.connectionsMu.Unlock()
}
