//go:build js && wasm

package aesctr

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"syscall/js"
)

const BufferSize int = 16 * 1024
const IvSize int = 16
const V1 byte = 0x1
const hmacSize = sha512.Size

var global = js.Global()
var uint8Array = global.Get("Uint8Array")
var arrayBuffer = global.Get("ArrayBuffer")

var (
	// ErrInvalidHMAC for authentication failure
	ErrInvalidHMAC = errors.New("invalid HMAC")
	ErrSystem      = func(msg string) error {
		return fmt.Errorf("system error %v", msg)
	}
	ErrInvalidParameters = errors.New("invalid parameters")
)

// Encrypt the stream using the given AES-CTR and SHA512-HMAC key
// @param in ArrayBuffer
// @param outFun function(chunk)
func Encrypt(in js.Value, outFun js.Value, keyAES, keyHMAC js.Value) (err error) {
	if in.Get("byteLength").Int() == 0 {
		return ErrInvalidParameters
	}
	iv := make([]byte, IvSize)
	_, err = rand.Read(iv)
	if err != nil {
		return ErrSystem(err.Error())
	}

	keyAESBytes := make([]byte, keyAES.Get("byteLength").Int())
	if js.CopyBytesToGo(keyAESBytes, keyAES) == 0 {
		return ErrInvalidParameters
	}
	keyHMACBytes := make([]byte, keyHMAC.Get("byteLength").Int())
	if js.CopyBytesToGo(keyHMACBytes, keyHMAC) == 0 {
		return ErrInvalidParameters
	}

	AES, err := aes.NewCipher(keyAESBytes)
	if err != nil {
		return ErrSystem(err.Error())
	}

	ctr := cipher.NewCTR(AES, iv)
	HMAC := hmac.New(sha512.New, keyHMACBytes)

	ch1 := uint8Array.New(1)
	if js.CopyBytesToJS(ch1, []byte{V1}) == 0 {
		return ErrSystem("version convert")
	}
	outFun.Invoke(ch1)
	_, err = HMAC.Write(iv)
	if err != nil {
		return
	}
	ch1 = uint8Array.New(IvSize)
	if js.CopyBytesToJS(ch1, iv) == 0 {
		return ErrSystem("iv convert")
	}
	outFun.Invoke(ch1)

	offset := 0
	buf := uint8Array.New(0)
	for {
		buf = uint8Array.New(in.Call("slice", offset, offset+BufferSize))
		bl := buf.Get("byteLength").Int()
		if bl == 0 {
			break
		}
		if bl != 0 {
			goBytes := make([]byte, bl)
			if js.CopyBytesToGo(goBytes, buf) == 0 {
				return ErrSystem("read bytes convert")
			}
			buf = uint8Array.New(0)
			outBuf := make([]byte, bl)

			ctr.XORKeyStream(outBuf, goBytes[:bl])
			goBytes = nil
			_, err = HMAC.Write(outBuf)
			if err != nil {
				return err
			}
			jsBytes := uint8Array.New(len(outBuf))
			if ii := js.CopyBytesToJS(jsBytes, outBuf); ii == 0 {
				return ErrSystem("encrypted bytes convert")
			}
			outBuf = nil
			outFun.Invoke(jsBytes)
			jsBytes = uint8Array.New(0)
			offset += bl
		}
	}

	sum := HMAC.Sum(nil)
	ch1 = uint8Array.New(hmacSize)
	if js.CopyBytesToJS(ch1, sum) == 0 {
		return ErrSystem("hmac bytes convert")
	}
	outFun.Invoke(ch1)
	return err
}

// Decrypt the stream and verify HMAC using the given AES-CTR and SHA512-HMAC key
// Do not trust the out io.Writer contents until the function returns the result
// of validating the ending HMAC hash.
// @param in ArrayBuffer
// @param outFun function(chunk)
func Decrypt(in js.Value, outFun js.Value, keyAES, keyHMAC js.Value) (err error) {
	keyAESBytes := make([]byte, keyAES.Get("byteLength").Int())
	ii := js.CopyBytesToGo(keyAESBytes, keyAES)
	if ii == 0 {
		return ErrInvalidParameters
	}
	keyHMACBytes := make([]byte, keyHMAC.Get("byteLength").Int())
	ii = js.CopyBytesToGo(keyHMACBytes, keyHMAC)
	if ii == 0 {
		return ErrInvalidParameters
	}

	offset := 0
	// Read version (up to 0-255)
	var version int8
	jsVersion := uint8Array.New(in.Call("slice", offset, 1))
	goVersion := make([]byte, 1)
	if js.CopyBytesToGo(goVersion, jsVersion) == 0 {
		return ErrSystem("1")
	}
	offset += 1

	version = int8(goVersion[0])
	if version != int8(V1) {
		return ErrSystem("version convert")
	}
	iv := make([]byte, IvSize)
	jsIv := uint8Array.New(in.Call("slice", offset, offset+IvSize))
	if jsIv.Get("byteLength").Int() == 0 {
		return ErrSystem("iv size calculate")
	}
	if js.CopyBytesToGo(iv, jsIv) == 0 {
		return ErrSystem("iv convert")
	}
	offset += IvSize

	AES, err := aes.NewCipher(keyAESBytes)
	if err != nil {
		return
	}

	ctr := cipher.NewCTR(AES, iv)
	h := hmac.New(sha512.New, keyHMACBytes)
	h.Write(iv)
	mac := make([]byte, hmacSize)

	b := uint8Array.New(0)
	var limit int
	for {
		b = uint8Array.New(in.Call("slice", offset, offset+BufferSize))
		bl := b.Get("byteLength").Int()
		if bl == 0 {
			break
		}
		gb := make([]byte, bl)
		if js.CopyBytesToGo(gb, b) == 0 {
			return ErrSystem("read bytes convert")
		}

		limit = bl - hmacSize
		// We reached the end
		if limit == 0 {
			if bl < hmacSize {
				return errors.New("not enough left")
			}

			copy(mac, gb[bl-hmacSize:bl])

			if bl == hmacSize {
				break
			}
		}

		h.Write(gb[:limit])

		// We always leave at least hmacSize bytes left in the buffer
		// That way, our next Peek() might be EOF, but we will still have enough
		b = uint8Array.New(in.Call("slice", offset, offset+len(gb[:limit])))
		bl = b.Get("byteLength").Int()
		if bl == 0 {
			break
		}
		gb = make([]byte, bl)
		//fmt.Println(b)
		if js.CopyBytesToGo(gb, b) == 0 {
			return ErrSystem("read bytes convert")
		}

		outBuf := make([]byte, int64(limit))
		ctr.XORKeyStream(outBuf, gb[:limit])

		gb = nil

		jsBytes := uint8Array.New(len(outBuf))
		if js.CopyBytesToJS(jsBytes, outBuf) == 0 {
			return ErrSystem("decrypted bytes convert")
		}
		outBuf = nil
		outFun.Invoke(jsBytes)
		jsBytes = uint8Array.New(0)
		offset += bl
	}

	if !hmac.Equal(mac, h.Sum(nil)) {
		return ErrInvalidHMAC
	}

	return nil
}
