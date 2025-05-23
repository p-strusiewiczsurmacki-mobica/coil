package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
)

type echoHandler struct {
	withRemoteAddrReply bool
}

func (h echoHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("content-type", "application/octet-stream")

	if h.withRemoteAddrReply {
		remote, _, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		remote += "|"
		w.Write([]byte(remote))
	}
	w.Write(body)
}

func main() {
	fmt.Println("Starting")
	var withRemoteAddress bool
	var port int
	flag.BoolVar(&withRemoteAddress, "reply-remote", false, "if set, echo-server will reply with remote host address (default: false)")
	flag.IntVar(&port, "port", 80, "configure port (default: 80)")
	flag.Parse()

	s := &http.Server{
		Addr: fmt.Sprintf(":%d", port),
		Handler: echoHandler{
			withRemoteAddrReply: withRemoteAddress,
		},
	}

	if err := s.ListenAndServe(); err != nil {
		fmt.Println("Error", err.Error())
	}

}
