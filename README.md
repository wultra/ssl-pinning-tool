# Dynamic SSL Pinning Utility Tool

## Prepare Data Using Java Utility

// TODO:

## Prepare Data Using OpenSSL

In case you have your SSL certificate in a `pem` format, you are able to generate all necessary data using OpenSSL.

### Generate a Key Pair

This command will generate a new ECDSA key pair and store it in the `keypair.pem` file. You need to store this file securely.

```sh
openssl ecparam -name prime256v1 -genkey -noout > keypair.pem
```

**Store the key pair safely! You will need it next time you replace SSL certificate to generate new signatures.**

### Prepare a Certificate Fingerprint

This sequence of commands converts a server certificate stored in the `cert.pem` file to fingerprint encoded as Base64 and stored in `fingerprint.txt` file.

```sh
# Convert PEM to DER format
openssl x509 -in cert.pem -inform PEM -outform DER -out cert.der

# Compute SHA256 digest
openssl dgst -sha256 < cert.der > fingerprint_raw.txt

# Encode the digest as Base64
openssl enc -base64 -A < fingerprint_raw.txt > fingerprint.txt
```

## Get Certificate Attributes

In order to compute the signature, you need to have values of certificate common name and expiration timestamp.

To obtain common name, call:

```sh
openssl x509 -noout -subject -inform der -in cert.der | sed -n '/^subject/s/^.*CN=//p'
```

To obtain expiration timestamp, call:

```sh
openssl x509 -noout -dates -inform der -in cert.der  | grep notAfter
```

Then, you need to convert the expiration timestamp to Unix epoch format (seconds after 1970/01/01).

### Sign Certificate Fingerprint

This sequence of commands signs the fingerprint from `fingerprint.txt` with the private key from the provided key pair file `keypair.pem` and stores the result signature as a Base64 encoded file `sign.txt`.

```sh
# Prepare a signature base string as $COMMON_NAME + '&' + $UNIXTIMESTAMP_EXPIRATION + '&' + $FINGERPRINT
echo "$COMMON_NAME" > signature_base_string.txt
echo "&" >> signature_base_string.txt
echo "$UNIXTIMESTAMP_EXPIRATION" >> signature_base_string.txt
echo "&" >> signature_base_string.txt
cat fingerprint.txt >> signature_base_string.txt

# Sign the signature base string with private key from the key pair
openssl dgst -sha1 -sign keypair.pem signature_base_string.txt > sign_raw.txt

# Encode result as Base64
openssl enc -base64 -A < sign_raw.txt > sign.txt
```

### Prepare the JSON

You need to encode the data into following JSON object:

```json
{
  "fingerprints": [
    {
      "name": "$COMMON_NAME:*.example.com",
      "fingerprint": "$FINGERPRINT_BASE64",
      "expires": $UNIXTIMESTAMP_EXPIRATION:1535709224,
      "signature": "$SIGNATURE_BASE64"
    }
  ]
}
```
