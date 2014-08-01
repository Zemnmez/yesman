//A bare bones openid servr who is comfortable
//with you being whoever you want to be.
package yesman

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type XRDSXml struct {
	//for pentesting XSS exploits,
	//defaults to /login.
	LoginURI string
}

func (x XRDSXml) ServeHTTP(rw http.ResponseWriter, rq *http.Request) {
	u := x.LoginURI
	if u == "" {
		u = "http://" + rq.Host + "/login"
	}

	io.Copy(
		rw,
		strings.NewReader(`<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds" xmlns="xri://$xrd*($v*2.0)">
	<XRD>
		<Service priority="0">
			<Type>http://specs.openid.net/auth/2.0/server</Type>		
			<URI>`+u+`</URI>
		</Service>
	</XRD>
</xrds:XRDS>`),
	)
}

func Login(rw http.ResponseWriter, rq *http.Request) {
	rq.ParseForm()
	switch rq.Form.Get("openid.mode") {
	case "associate":
		//form shared secret
		kv, err := Associate(rq.Form)
		if err != nil {
			fmt.Fprintln(rw, err)
		}

		fmt.Fprintf(rw, "%s", kv)

	case "checkid_setup":
		err := SetupHandler(rw, rq)
		if err != nil {
			fmt.Fprintln(rw, err)
		}
	case "check_authentication":
		kv := KeyValue{
			"openid.mode": "id_res",
			"is_valid":    "true",
		}

		fmt.Fprintf(rw, "%s", kv)
	}
}

func SetupHandler(rw http.ResponseWriter, rq *http.Request) (err error) {
	rw.Header().Set("Content-Type", "text/html")
	s := "<!DOCTYPE HTML><head><title>yesman</title>" +
		"<style type='text/css'>input{display:block;width:100%}input:before{content:attr(name)}</style>" +
		"</head><body><h1>Who would you like to be today?</h1><form " +
		"action=/forward method=post " +
		"id=f>"

	if err = rq.ParseForm(); err != nil {
		return
	}

	if rq.Form.Get("openid.identity") != "" && rq.Form.Get("openid.claimed_id") == "" {
		rq.Form.Set("openid.claimed_id", " -- unset -- ")
	}

	for k, vl := range rq.Form {
		for _, v := range vl {
			s += "<input name='" + html.EscapeString(k) + "' value='" + html.EscapeString(v) + "'>"
		}
	}

	s += "<input type=submit></form>" +
		"</body>"

	if _, err = io.Copy(rw, strings.NewReader(s)); err != nil {
		return
	}

	return
}

func ForwardHandler(rw http.ResponseWriter, rq *http.Request) {
	err := rq.ParseForm()
	if err != nil {
		fmt.Fprintf(rw, "%s", err)
		return
	}

	values, err := Forward(rq.Form)

	rq.Form.Set("openid.op_endpoint", "http://"+rq.Host+"/login")

	if err != nil {
		fmt.Fprintf(rw, "%s", err)
		return
	}

	rw.Header().Set(
		"Location",
		rq.Form.Get("openid.return_to")+
			"?"+values.Encode(),
	)

	rw.WriteHeader(302)
}

var toSign = []string{"mode", "identity", "assoc_handle", "return_to"}

func Forward(v url.Values) (ov url.Values, err error) {
	//just say yes.

	log.Println("Got forward, forwarding...")
	if !strings.HasPrefix(v.Get("openid.return_to"), "http") {
		err = errors.New("Will not return to non-http URLs.")
		return
	}

	var handle uint64
	if hStr := v.Get("openid.assoc_handle"); hStr != "" {
		handle, err = strconv.ParseUint(hStr, 10, 0)
		if err != nil {
			return
		}
	} else {
		v.Set("openid.assoc_handle", "1")
	}

	ov = v

	ov.Set("openid.mode", "id_res")

	//:¬)
	ov.Set("openid.assoc_handle", "1")

	ov.Set("openid.signed", strings.Join(toSign, ","))

	var (
		a  Association
		ok bool
	)

	if a, ok = associations[handle]; !ok {
		ov.Set(
			"openid.invalidate_handle",
			strconv.FormatUint(handle, 10),
		)
		return
	}

	var sigVl = make(KeyValue, len(toSign))

	for _, v := range toSign {
		sigVl[v] = ov.Get("openid." + v)
	}

	var mac = make([]byte, 20)
	macWriter := hmac.New(sha1.New, a.MacSecret[:])
	_, err = macWriter.Write(
		[]byte(sigVl.String()),
	)

	if err != nil {
		err = fmt.Errorf("Failed to compute MAC: %s", err)
		return
	}

	ov.Set("openid.sig", base64.StdEncoding.EncodeToString(mac))

	return
}

var one = big.NewInt(1)

type KeyValue map[string]string

func (k KeyValue) String() string {
	var s = make([]string, 0, len(k))
	for k, v := range k {
		s = append(s, k+":"+v)
	}
	return strings.Join(s, "\n")
}

type Server struct {
	// /openid endpoint
	Openid http.Handler
	// /login endpoint
	Login http.Handler

	//forwarding endpoint
	Forward http.Handler
	m       *http.ServeMux
}

func (s Server) ServeHTTP(rw http.ResponseWriter, rq *http.Request) {
	log.Println(rq.RequestURI, "->", rq.UserAgent(), rq.RemoteAddr)

	switch rq.URL.Path {
	case "/openid":
		s.Openid.ServeHTTP(rw, rq)
	case "/login":
		s.Login.ServeHTTP(rw, rq)
	case "/forward":
		s.Forward.ServeHTTP(rw, rq)
	}
}
