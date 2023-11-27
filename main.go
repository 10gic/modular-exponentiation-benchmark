package main

// #cgo LDFLAGS: -lcrypto
// #include <openssl/bn.h>
// #include <openssl/err.h>
//
// static int BN_num_bytes_macro_wrapper(BIGNUM* arg) {
//   return BN_num_bytes(arg);
// }
import "C"
import (
	"fmt"
	"math/big"
	"time"
	"unsafe"

	"github.com/cronokirby/saferith"
)

// ModExp calculates modular exponentiation using native Exp method from big package.
// It is not a cryptographically constant-time operation. May be subject to side channel attack
func ModExp(base, exponent, modulus *big.Int) *big.Int {
	return new(big.Int).Exp(base, exponent ,modulus)
}

// ModExpGo3rdParty calculates modular exponentiation using cronokirby/saferith package.
// It is a cryptographically constant-time operation.
func ModExpGo3rdParty(base, exp, mod *big.Int) *big.Int {
	b := new(saferith.Nat).SetBytes(base.Bytes())
	e := new(saferith.Nat).SetBytes(exp.Bytes())
	m := saferith.ModulusFromBytes(mod.Bytes())

	return new(saferith.Nat).Exp(b, e, m).Big()
}

// ModExpOpenSSL calculates modular exponentiation using OpenSSL function BN_mod_exp_mont_consttime.
// It is a cryptographically constant-time operation.
func ModExpOpenSSL(base, exp, mod *big.Int) *big.Int {
	// Convert big.Int types to BIGNUM types
	baseBn := C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&base.Bytes()[0])), C.int(len(base.Bytes())), nil)
	expBn := C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&exp.Bytes()[0])), C.int(len(exp.Bytes())), nil)
	modBn := C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&mod.Bytes()[0])), C.int(len(mod.Bytes())), nil)

	// Create a new BIGNUM to store the result
	resultBn := C.BN_new()

	// Create a new BN_CTX for temporary variables
	ctx := C.BN_CTX_new()

	// Call BN_mod_exp_mont_consttime to perform modular exponentiation
	rv := C.BN_mod_exp_mont_consttime(resultBn, baseBn, expBn, modBn, ctx, nil)
	if rv != 1 {
		errCode := C.ERR_get_error()
		errMsg := C.ERR_error_string(errCode, nil)
		panic(fmt.Errorf("BN_mod_exp_mont_consttime failed: %v", C.GoString(errMsg)))
	}

	// Convert the result back to a big.Int type
	resultBytes := make([]byte, int(C.BN_num_bytes_macro_wrapper(resultBn)))
	C.BN_bn2bin(resultBn, (*C.uchar)(unsafe.Pointer(&resultBytes[0])))
	result := new(big.Int).SetBytes(resultBytes)

	// Free memory
	C.BN_free(baseBn)
	C.BN_free(expBn)
	C.BN_free(modBn)
	C.BN_free(resultBn)
	C.BN_CTX_free(ctx)

	return result
}

func hex2bigint(input string) *big.Int {
	i := new(big.Int)
	i.SetString(input, 16)

	return i
}

func main() {
	base := hex2bigint("005D29206611838F1D02F3B54C92B746AA2660B4A1153586176D5B431D72CFE1A8AE6E7D565A5B214EFABF82689E5E973BCEBE2E71ACC710C4B40B7D014BA170DE2119B14661E62BEC98722616081BC817F78C73817531FEF353037798BFE27CD05DF957C738136D5D28F3EFF0815B1283645A3C83F40503732606671DCB4873C72AEDD5CD6BCAA250DC3D06C78A79F81794C542E741D7C9F67F84AD749FEDEB75370A3C2837D2C8C292C6274618FE1B89119BB5AF82096E4317479BFCF68B7D1498E4F292FA4064A35B6A0940EEAB28B6EF2FEEAA56EE4D8BDB4CDC38672651F5E82643FFD3228BFC2680F3BC1887AD8B8356EFB9D2EA8BB383F7FCFF5F6D5F")
	exp := hex2bigint("4F63A3C6F683901B562E8581052152A55E3B6D7FB9BA1E6DF48341A33353884CE787CFE361999FDFD977FACB5B6276B15F7CF1F17933425C088C1569277CF0FC5DE05A6D9778210AB9927FD7077EB8160E3B7BC4C51E33E4181F0F3060CCBFD8")
	mod := hex2bigint("942EBBCEEC7554B7D3E8064FB763B95D03D4E3FCBFCBF6B76A20F09EAD765AD443B5F01FCFF6033E013972584695CC33742B55C96E95EEE105692AC885191F39462B1DC9FAC1BE077D1F0F723E739CFA3170C04BE9B0E336843D79B803181F4C6892FBB0551DB36554ABA70FCB9FE16610251AEB69F79AE14A9ABC0D2426CBCF798FC4A2D849187699D05C7AF997698AA0C35529C95AB0FB0E301DA1160108A2F9059F2C9EB7ECD464202DBF98F13DE2DD1ADF766D0AF086D97B4BA5577213992D6FBE1ACBF14585A3FD2F2EA34E894A08B2CA8BFEB3ED485348410FED3925AD48DB0C9D254E28E6191CD4D427265F8F9F4EC5321EC6C99955587D232C75D1D9")

	start := time.Now()
	result := ModExp(base, exp, mod)
	fmt.Printf("ModExp result %X\n", result)
	fmt.Printf("ModExp took %v\n", time.Since(start))

	start = time.Now()
	result = ModExpGo3rdParty(base, exp, mod)
	fmt.Printf("ModExpGo3rdParty result %X\n", result)
	fmt.Printf("ModExpGo3rdParty took %v\n", time.Since(start))

	start = time.Now()
	result = ModExpOpenSSL(base, exp, mod)
	fmt.Printf("ModExpOpenSSL result %X\n", result)
	fmt.Printf("ModExpOpenSSL took %v\n", time.Since(start))
}
