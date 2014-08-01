//A bare bones openid servr who is comfortable
//with you being whoever you want to be.
package yesman

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
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
		values, err := Setup(rq.Form)
		if err != nil {
			fmt.Fprintln(rw, err)
		}

		rw.Header().Set(
			"Location",
			rq.Form.Get("openid.return_to")+
				"?" + values.Encode(),
		)
	case "check_authentication":
		kv := KeyValue {
			"openid.mode":"id_res",
			"is_valid":"true",
		}

		fmt.Fprintf(rw, "%s", kv)
	}
}

func Setup(v url.Values) (ov url.Values, err error) {
	//just say yes.

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
		err = errors.New("Missing assoc_handle.")
		return
	}

	ov = v

	ov.Set("openid.signed", "mode,identity,return_to")

	var(
		a Association
		ok bool
	)

	if a, ok = associations[handle]; !ok {
		ov.Set(
			"openid.invalidate_handle",
			strconv.FormatUint(handle, 10),
		)
		return
	}

	var sigVl = make(KeyValue, 3)

	sigVl["mode"] = ov.Get("openid.mode")
	sigVl["identity"] = ov.Get("openid.identity")
	sigVl["return_to"] = ov.Get("return_to")

	var mac = make([]byte, 20)
	macWriter :=  hmac.New(sha1.New, a.MacSecret[:])
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

func(k KeyValue) String() string {
	var s = make([]string, 0, len(k))
	for k, v := range k {
		s = append(s, k + ":"+v)
	}
	return strings.Join(s, "\n")
}

type Server struct {
	// /openid endpoint
	Openid http.Handler
	// /login endpoint
	Login http.Handler
	m     *http.ServeMux
}

func (s Server) ServeHTTP(rw http.ResponseWriter, rq *http.Request) {
	log.Println(rq.RequestURI, "->", rq.UserAgent(), rq.RemoteAddr)

	switch rq.URL.Path {
	case "/openid":
		s.Openid.ServeHTTP(rw, rq)
	case "/login":
		s.Login.ServeHTTP(rw, rq)
	}
}

