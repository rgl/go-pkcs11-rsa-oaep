[![Build status](https://github.com/rgl/go-pkcs11-rsa-oaep/workflows/Build/badge.svg)](https://github.com/rgl/go-pkcs11-rsa-oaep/actions?query=workflow%3ABuild)

# About

This implements [RSAES-OAEP-PKCS1-v2_1 (aka RSAES-OAEP; aka RSA-OAEP; aka OAEP)](https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding)
in [SmartCard-HSM 4K](https://www.smartcard-hsm.com/) based PKCS#11 HSMs.

These cards only implement the deprecated RSAES-PKCS1-v1_5:

* [SmartCard-HSM-4K-Mini-SIM](https://www.smartcard-hsm.com/docs/sc-hsm-4k-datasheet.pdf)
* [Nitrokey HSM 2](https://www.nitrokey.com/#comparison)

This was based on the [Go crypto/rsa package source code](https://github.com/golang/go/blob/go1.15/src/crypto/rsa/rsa.go).

See an example application at https://github.com/rgl/go-pkcs11-rsa-oaep-example.

# Test

Execute the following instructions in a Ubuntu 20.04 terminal.

Install dependencies:

```bash
sudo apt-get install -y opensc softhsm2
```

## SoftHSM2

Then run the tests:

```bash
./test.sh
```

## SmartCard-HSM-4K-Mini-SIM

Set the needed environment variables:

```bash
export TEST_PKCS11_LIBRARY_PATH='/usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so'
export TEST_PKCS11_SO_PIN=3537363231383830
export TEST_PKCS11_USER_PIN=648219
export TEST_PKCS11_TOKEN_LABEL=test-token
export TEST_PKCS11_KEY_LABEL=test-rsa-2048
```

Inititialize the HSM device:

```bash
pkcs11-tool \
    --module opensc-pkcs11.so \
    --init-token \
    --init-pin \
    --so-pin $TEST_PKCS11_SO_PIN \
    --pin $TEST_PKCS11_USER_PIN \
    --label $TEST_PKCS11_TOKEN_LABEL
```

The output should be:

```
Using slot 0 with a present token (0x0)
Token successfully initialized
User PIN successfully initialized
```

Create the test-key-2048 RSA key:

```bash
pkcs11-tool \
    --module opensc-pkcs11.so \
    --login \
    --keypairgen \
    --key-type rsa:2048 \
    --id 10 \
    --label $TEST_PKCS11_KEY_LABEL \
    --pin $TEST_PKCS11_USER_PIN
```

The output should be:

```
Using slot 0 with a present token (0x0)
Key pair generated:
Private Key Object; RSA
  label:      test-rsa-2048
  ID:         10
  Usage:      decrypt, sign, unwrap
  Access:     none
Public Key Object; RSA 2048 bits
  label:      test-rsa-2048
  ID:         10
  Usage:      encrypt, verify, wrap
  Access:     none
```

List the objects:

```bash
pkcs11-tool --module opensc-pkcs11.so --list-slots --list-objects
```

The output should be:

```
Available slots:
Slot 0 (0x0): Alcor Micro AU9560 00 00
  token label        : test-token (UserPIN)
  token manufacturer : www.CardContact.de
  token model        : PKCS#15 emulated
  token flags        : login required, rng, token initialized, PIN initialized
  hardware version   : 24.13
  firmware version   : 3.1
  serial num         : DECC0800102
  pin min/max        : 6/15
Using slot 0 with a present token (0x0)
Public Key Object; RSA 2048 bits
  label:      test-rsa-2048
  ID:         10
  Usage:      encrypt, verify, wrap
  Access:     none
```

**NB** For some odd reason the token label always has the ` (UserPIN)`
       suffix... so we must account for that when executing the tests.

Then run the tests:

```bash
TEST_PKCS11_TOKEN_LABEL="$TEST_PKCS11_TOKEN_LABEL (UserPIN)" \
    go test -v
```
