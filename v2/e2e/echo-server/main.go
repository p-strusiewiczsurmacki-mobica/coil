package main

import (
	"io"
	"net/http"
	"os"
)

type echoHandler struct {
	withReply bool
}

func (h echoHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("content-type", "application/octet-stream")
	w.Write(body)
	if h.withReply {
		w.Write([]byte(req.Host))
	}

}

func main() {
	withReply := false
	if len(os.Args) > 1 {
		if os.Args[1] == "reply" {
			withReply = true
		}
	}
	s := &http.Server{
		Handler: echoHandler{
			withReply: withReply,
		},
	}
	s.ListenAndServe()
}
