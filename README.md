# Dynamic SSL Pinning Utility Tool

## Prepare Data Using Java Utility

// TODO:

## Prepare Data Using OpenSSL

### Generate a Key Pair

This command will generate a new ECDSA key pair and store it in the `keypair.pem` file. You need to store this file securely.

```sh
openssl ecparam -name prime256v1 -genkey -noout > keypair.pem
```

### Prepare a Certificate Fingerprint

This sequence of commands converts a server certificate stored in the `cert.pem` file to fingerprint encoded as Base64 and stored in `fingerprint.txt` file.

```sh
# Convert PEM to DER format
openssl x509 -in cert.pem -inform PEM -outform DER -out key.der

# Compute SHA256 digest
openssl dgst -sha256 < key.der > fingerprint_raw.txt

# Encode the digest as Base64
openssl enc -base64 -A < fingerprint_raw.txt > fingerprint.txt
```

### Sign Certificate Fingerprint

This sequence of commands signs the fingerprint from `fingerprint.txt` with the private key from the provided key pair file `keypair.pem` and stores the result signature as a Base64 encoded file `sign.txt`.

```sh
echo "$UNIXTIMESTAMP_EXPIRATION" > signature_base_string.txt
echo "&" >> signature_base_string.txt
cat fingerprint.txt >> signature_base_string.txt
openssl dgst -sha1 -sign keypair.pem signature_base_string.txt > sign_raw.txt
openssl enc -base64 -A < sign_raw.txt > sign.txt
```

### Prepare the JSON

You need to encode the data into following JSON object:

```json
{
  "status": "OK",
  "responseObject": [
    {
      "name": "$COMMON_NAME",
      "fingerprint": "$FINGERPRINT_BASE64",
      "expires": $UNIXTIMESTAMP_EXPIRATION,
      "signature": "SIGNATURE_BASE64"
    }
  ]
}
```
