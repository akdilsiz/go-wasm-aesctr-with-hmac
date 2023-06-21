//go:build js && wasm

package aesctr

import (
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"syscall/js"
	"testing"
)

var console = global.Get("console")
var consoleLog = func(val js.Value) {
	console.Call("log", val)
}
var wd = func() string {
	wd, _ := os.Getwd()
	return wd
}

func TestEncrypt(t *testing.T) {
	coming := make([]js.Value, 0)
	comingFun := js.FuncOf(func(this js.Value, args []js.Value) any {
		coming = append(coming, args[0])
		return js.Undefined()
	})

	inFileGOBytes := []byte{12, 1, 3, 22, 5}
	arrBuff := global.Get("ArrayBuffer").New(5)
	arrValues := global.Get("Uint8Array").New(arrBuff)
	arrValues.SetIndex(0, inFileGOBytes[0])
	arrValues.SetIndex(1, inFileGOBytes[1])
	arrValues.SetIndex(2, inFileGOBytes[2])
	arrValues.SetIndex(3, inFileGOBytes[3])
	arrValues.SetIndex(4, inFileGOBytes[4])

	assert.Equal(t, 5, arrBuff.Get("byteLength").Int())

	keyAES, err := GenerateKey(32)
	assert.Nil(t, err)
	keyAESJSBytes := uint8Array.New(32)
	ii := js.CopyBytesToJS(keyAESJSBytes, keyAES)
	assert.Equal(t, 32, ii)

	keyHMAC, err := GenerateKey(32)
	assert.Nil(t, err)
	keyHMACJSBytes := uint8Array.New(32)
	ii = js.CopyBytesToJS(keyHMACJSBytes, keyHMAC)
	assert.Equal(t, 32, ii)

	err = Encrypt(arrBuff, comingFun.Value, keyAESJSBytes, keyHMACJSBytes)
	assert.Nil(t, err)
	assert.Equal(t, 1, coming[0].Get("byteLength").Int())
	assert.Equal(t, 16, coming[1].Get("byteLength").Int())
	assert.Equal(t, 5, coming[2].Get("byteLength").Int())
	assert.Equal(t, 64, coming[3].Get("byteLength").Int())
}

func TestDecrypt(t *testing.T) {
	coming := uint8Array.New(0)
	comingFun := js.FuncOf(func(this js.Value, args []js.Value) any {
		arr := global.Get("Uint8Array").New(coming.Get("byteLength").Int() + args[0].Get("byteLength").Int())
		arr.Call("set", coming, 0)
		arr.Call("set", args[0], coming.Get("byteLength").Int())
		coming = uint8Array.New(arr)
		return js.Undefined()
	})

	encoder := global.Get("TextEncoder").New()
	encoded := encoder.Call("encode", "selam")

	assert.Equal(t, 5, encoded.Get("byteLength").Int())

	keyAES, err := GenerateKey(32)
	assert.Nil(t, err)
	keyAESJSBytes := uint8Array.New(32)
	ii := js.CopyBytesToJS(keyAESJSBytes, keyAES)
	assert.Equal(t, 32, ii)

	keyHMAC, err := GenerateKey(32)
	assert.Nil(t, err)
	keyHMACJSBytes := uint8Array.New(32)
	ii = js.CopyBytesToJS(keyHMACJSBytes, keyHMAC)
	assert.Equal(t, 32, ii)

	err = Encrypt(encoded.Get("buffer"), comingFun.Value, keyAESJSBytes, keyHMACJSBytes)
	assert.Nil(t, err)

	assert.Equal(t, 5+1+16+64, coming.Get("byteLength").Int())

	comingOut := uint8Array.New(0)
	comingOutFun := js.FuncOf(func(this js.Value, args []js.Value) any {
		arr := global.Get("Uint8Array").New(comingOut.Get("byteLength").Int() + args[0].Get("byteLength").Int())
		arr.Call("set", comingOut, 0)
		arr.Call("set", args[0], comingOut.Get("byteLength").Int())
		comingOut = uint8Array.New(arr)
		return js.Undefined()
	})

	err = Decrypt(coming.Get("buffer"), comingOutFun.Value, keyAESJSBytes, keyHMACJSBytes)
	assert.Nil(t, err)

	decoder := global.Get("TextDecoder").New()
	decoded := decoder.Call("decode", comingOut)
	assert.Equal(t, js.ValueOf("selam"), decoded)
}

func TestDecrypt2(t *testing.T) {
	encryptedFilename := filepath.Join(wd(), "test", "file.encrypted")
	decryptedFilename := filepath.Join(wd(), "test", "file.decrypted")
	global.Get("fs").Call("truncateSync", encryptedFilename)
	global.Get("fs").Call("truncateSync", decryptedFilename)

	comingFun := js.FuncOf(func(this js.Value, args []js.Value) any {
		global.Get("fs").Call("appendFileSync",
			encryptedFilename,
			args[0])

		return js.Undefined()
	})

	keyAES, err := GenerateKey(32)
	assert.Nil(t, err)
	keyAESJSBytes := uint8Array.New(32)
	ii2 := js.CopyBytesToJS(keyAESJSBytes, keyAES)
	assert.Equal(t, 32, ii2)

	keyHMAC, err := GenerateKey(32)
	assert.Nil(t, err)
	keyHMACJSBytes := uint8Array.New(32)
	ii2 = js.CopyBytesToJS(keyHMACJSBytes, keyHMAC)
	assert.Equal(t, 32, ii2)

	saltFile := global.Get("fs").Call("readFileSync", filepath.Join(wd(), "test", "efetherock.jpg"))

	err = Encrypt(saltFile.Get("buffer"), comingFun.Value, keyAESJSBytes, keyHMACJSBytes)
	assert.Nil(t, err)

	// sync file
	_, _ = os.Stat(encryptedFilename)

	encryptedFileBuffer := global.Get("fs").Call("readFileSync", encryptedFilename)

	assert.Equal(t,
		saltFile.Get("byteLength").Int()+1+16+64,
		encryptedFileBuffer.Get("byteLength").Int())

	comingOutFun := js.FuncOf(func(this js.Value, args []js.Value) any {
		global.Get("fs").Call("appendFileSync",
			decryptedFilename,
			args[0],
			js.FuncOf(func(this js.Value, args2 []js.Value) any {
				return js.Undefined()
			}))
		return js.Undefined()
	})

	err = Decrypt(encryptedFileBuffer.Get("buffer"),
		comingOutFun.Value,
		keyAESJSBytes,
		keyHMACJSBytes)
	assert.Nil(t, err)

	_, _ = os.Stat(decryptedFilename)
	decryptedFileBuffer := global.Get("fs").Call("readFileSync", decryptedFilename)

	assert.Equal(t, saltFile.Get("byteLength"), decryptedFileBuffer.Get("byteLength"))

	global.Get("fs").Call("truncateSync", encryptedFilename)
	global.Get("fs").Call("truncateSync", decryptedFilename)
}
