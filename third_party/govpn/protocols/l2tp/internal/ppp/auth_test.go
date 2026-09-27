package ppp

import (
	"bytes"
	"crypto/md5"
	"testing"
)

func TestAutoAcceptsSupportedAuthentication(t *testing.T) {
	for name, authValue := range map[string][]byte{"pap": authPAP, "chap-md5": authCHAPMD5, "mschapv2": authMSCHAPv2} {
		t.Run(name, func(t *testing.T) {
			var sent [][]byte
			session := NewWithAuth("alice", "secret", "auto", transportFunc(func(frame []byte) error {
				sent = append(sent, append([]byte(nil), frame...))
				return nil
			}), &clientRecordHandler{})
			request := cpPacket{Code: codeConfigureRequest, ID: 7, Body: marshalOptions([]option{{Type: optAuthProto, Value: authValue}})}.marshal()
			session.Receive(encodeFrame(ProtocolLCP, request))
			if len(sent) != 1 {
				t.Fatalf("sent %d replies, want 1", len(sent))
			}
			protocol, payload, ok := decodeFrame(sent[0])
			if !ok || protocol != ProtocolLCP {
				t.Fatal("invalid LCP reply")
			}
			reply, ok := parseCP(payload)
			if !ok || reply.Code != codeConfigureAck {
				t.Fatalf("reply code = %d, want Configure-Ack", reply.Code)
			}
		})
	}
}

func TestForcedAuthenticationNaksDifferentMethod(t *testing.T) {
	var sent []byte
	session := NewWithAuth("alice", "secret", "pap", transportFunc(func(frame []byte) error { sent = append([]byte(nil), frame...); return nil }), &clientRecordHandler{})
	request := cpPacket{Code: codeConfigureRequest, ID: 9, Body: marshalOptions([]option{{Type: optAuthProto, Value: authMSCHAPv2}})}.marshal()
	session.Receive(encodeFrame(ProtocolLCP, request))
	_, payload, _ := decodeFrame(sent)
	reply, _ := parseCP(payload)
	options, _ := parseOptions(reply.Body)
	if reply.Code != codeConfigureNak || len(options) != 1 || !bytes.Equal(options[0].Value, authPAP) {
		t.Fatalf("reply = %#v options=%#v, want PAP Configure-Nak", reply, options)
	}
}

func TestBuildCHAPMD5Response(t *testing.T) {
	response := buildCHAPMD5Response(3, []byte("challenge"), "alice", "secret")
	want := md5.Sum(append(append([]byte{3}, []byte("secret")...), []byte("challenge")...))
	if len(response) != 1+md5.Size+len("alice") || response[0] != md5.Size || !bytes.Equal(response[1:1+md5.Size], want[:]) {
		t.Fatalf("unexpected CHAP-MD5 response: %x", response)
	}
}

func TestPAPMessage(t *testing.T) {
	if got := papMessage([]byte{2, 'o', 'k'}); got != "ok" {
		t.Fatalf("message = %q", got)
	}
	if got := papMessage([]byte{9, 'x'}); got != "authentication rejected" {
		t.Fatalf("malformed message = %q", got)
	}
}
