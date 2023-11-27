package main

import (
	"crypto/rand"
	"math/big"
	"testing"
)

func randBigInt(bitSize int) *big.Int {
	byteSize := (bitSize + 7) / 8 // example: if bitSize == 12, then byteSize == 2
	randomBytes := make([]byte, byteSize)

	_, err := rand.Read(randomBytes)
	if err != nil {
		panic(err)
	}

	return new(big.Int).SetBytes(randomBytes)
}

func randOddBigInt(bitSize int) *big.Int {
	byteSize := (bitSize + 7) / 8 // example: if bitSize == 12, then byteSize == 2
	randomBytes := make([]byte, byteSize)

	_, err := rand.Read(randomBytes)
	if err != nil {
		panic(err)
	}

	rv := new(big.Int).SetBytes(randomBytes)
	rv.SetBit(rv, 0 , 1) // Make sure it is odd (set last bit is 1)
	return rv
}

func BenchmarkModExp256(b *testing.B) {
	x := randBigInt(256)
	e := randBigInt(96)
	m := randOddBigInt(256)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ModExp(x, e, m)
	}
}

func BenchmarkModExpGo3rdParty256(b *testing.B) {
	x := randBigInt(256)
	e := randBigInt(96)
	m := randOddBigInt(256)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ModExpGo3rdParty(x, e, m)
	}
}

func BenchmarkModExpOpenSSL256(b *testing.B) {
	x := randBigInt(256)
	e := randBigInt(96)
	m := randOddBigInt(256)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ModExpOpenSSL(x, e, m)
	}
}

func BenchmarkModExp2048(b *testing.B) {
	x := randBigInt(2048)
	e := randBigInt(768)
	m := randOddBigInt(2048)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ModExp(x, e, m)
	}
}

func BenchmarkModExpGo3rdParty2048(b *testing.B) {
	x := randBigInt(2048)
	e := randBigInt(768)
	m := randOddBigInt(2048)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ModExpGo3rdParty(x, e, m)
	}
}

func BenchmarkModExpOpenSSL2048(b *testing.B) {
	x := randBigInt(2048)
	e := randBigInt(768)
	m := randOddBigInt(2048)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ModExpOpenSSL(x, e, m)
	}
}
