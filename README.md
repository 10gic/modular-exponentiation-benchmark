# Introduction
[Modular exponentiation](https://en.wikipedia.org/wiki/Modular_exponentiation) is a time-consuming operation, and this project has performed a Golang benchmark test on three different implementations.

| Method           | Note                                    | Is Constant-Time | Run Time (Small Parameter) | Run Time (Big Parameter) |
|------------------|-----------------------------------------|------------------|----------------------------|--------------------------|
| ModExp           | Use Golang builtin big package          | No 😢            | 17532 ns 😊                | 2281780 ns               |
| ModExpGo3rdParty | Use cronokirby/saferith package         | Yes 😊           | 28941 ns 😢                | 6000609 ns 😢            |
| ModExpOpenSSL    | Use OpenSSL (BN_mod_exp_mont_consttime) | Yes 😊           | 20389 ns                   | 1325081 ns 😊            |

1. Constant-time is important for security because it prevents attackers from using timing analysis to deduce sensitive information about the input data
2. Test CPU: Intel(R) Core(TM) i7-4770HQ CPU @ 2.20GHz
3. Small Parameter: 256 bits base/96 bits exponent/256 bits modulus
4. Big Parameter: 2048 bits base/768 bits exponent/2048 bits modulus

# Conclusion
1. If you are using it in a cryptography scenario, please choose ModExpGo3rdParty or ModExpOpenSSL.
2. If you are using it in a cryptography scenario and performance is a major concern, please choose ModExpOpenSSL.

# Test
```shell
$ go test -bench .
goos: darwin
goarch: amd64
pkg: github.com/10gic/modular-exponentiation-benchmark
cpu: Intel(R) Core(TM) i7-4770HQ CPU @ 2.20GHz
BenchmarkModExp256-8                       69508             17532 ns/op
BenchmarkModExpGo3rdParty256-8             41390             28941 ns/op
BenchmarkModExpOpenSSL256-8                58264             20389 ns/op
BenchmarkModExp2048-8                        520           2281780 ns/op
BenchmarkModExpGo3rdParty2048-8              199           6000609 ns/op
BenchmarkModExpOpenSSL2048-8                 904           1325081 ns/op
PASS
ok      github.com/10gic/modular-exponentiation-benchmark       9.169s
```
