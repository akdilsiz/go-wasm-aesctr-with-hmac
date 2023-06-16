//go:build js && wasm

package aesctr

import (
	"github.com/stretchr/testify/assert"
	"io"
	"os"
	"path/filepath"
	"syscall/js"
	"testing"
)

var global = js.Global()
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
	keyHMAC, err := GenerateKey(32)

	err = Encrypt(arrBuff, comingFun.Value, keyAES, keyHMAC)
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
	keyHMAC, err := GenerateKey(32)

	err = Encrypt(encoded.Get("buffer"), comingFun.Value, keyAES, keyHMAC)
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

	err = Decrypt(coming.Get("buffer"), comingOutFun.Value, keyAES, keyHMAC)
	assert.Nil(t, err)

	decoder := global.Get("TextDecoder").New()
	decoded := decoder.Call("decode", comingOut)
	assert.Equal(t, js.ValueOf("selam"), decoded)
}

func TestDecrypt2(t *testing.T) {
	coming := uint8Array.New(0)
	comingFun := js.FuncOf(func(this js.Value, args []js.Value) any {
		arr := global.Get("Uint8Array").New(coming.Get("byteLength").Int() + args[0].Get("byteLength").Int())
		arr.Call("set", coming, 0)
		arr.Call("set", args[0], coming.Get("byteLength").Int())
		coming = uint8Array.New(arr)
		return js.Undefined()
	})

	f, err := os.Open(filepath.Join(wd(), "test", "efetherock.jpg"))
	assert.Nil(t, err)
	bytes, err := io.ReadAll(f)
	assert.Nil(t, err)
	err = f.Close()
	assert.Nil(t, err)

	jsBytes := uint8Array.New(len(bytes))
	ii := js.CopyBytesToJS(jsBytes, bytes)
	assert.Equal(t, len(bytes), ii)

	assert.Equal(t, ii, jsBytes.Get("byteLength").Int())
	keyAES, err := GenerateKey(32)
	assert.Nil(t, err)
	keyHMAC, err := GenerateKey(32)

	err = Encrypt(jsBytes.Get("buffer"), comingFun.Value, keyAES, keyHMAC)
	assert.Nil(t, err)

	assert.Equal(t, ii+1+16+64, coming.Get("byteLength").Int())

	comingOut := uint8Array.New(0)
	comingOutFun := js.FuncOf(func(this js.Value, args []js.Value) any {
		arr := global.Get("Uint8Array").New(comingOut.Get("byteLength").Int() + args[0].Get("byteLength").Int())
		arr.Call("set", comingOut, 0)
		arr.Call("set", args[0], comingOut.Get("byteLength").Int())
		comingOut = uint8Array.New(arr)
		return js.Undefined()
	})

	err = Decrypt(coming.Get("buffer"), comingOutFun.Value, keyAES, keyHMAC)
	assert.Nil(t, err)

	goBytes := make([]byte, len(bytes))
	iii := js.CopyBytesToGo(goBytes, comingOut)
	assert.Equal(t, iii, ii)
	assert.Equal(t, bytes, goBytes)
}
