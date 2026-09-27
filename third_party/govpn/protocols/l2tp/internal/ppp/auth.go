package ppp

import (
	"crypto/md5"
)

const (
	papAuthenticateRequest = 1
	papAuthenticateAck     = 2
	papAuthenticateNak     = 3
)

func papMessage(body []byte) string {
	if len(body) == 0 || int(body[0]) > len(body)-1 {
		return "authentication rejected"
	}
	return string(body[1 : 1+int(body[0])])
}

func parseCHAPMD5Challenge(body []byte) ([]byte, bool) {
	if len(body) < 1 || body[0] == 0 || int(body[0]) > len(body)-1 {
		return nil, false
	}
	return body[1 : 1+int(body[0])], true
}

func buildCHAPMD5Response(id byte, challenge []byte, username, password string) []byte {
	hash := md5.New()
	_, _ = hash.Write([]byte{id})
	_, _ = hash.Write([]byte(password))
	_, _ = hash.Write(challenge)
	digest := hash.Sum(nil)
	body := make([]byte, 1, 1+len(digest)+len(username))
	body[0] = byte(len(digest))
	body = append(body, digest...)
	body = append(body, username...)
	return body
}
