# Dynamic SSL Pinning Utility Tool

The SSL pinning utility tool is used to sign SSL certificates.

You can use either of the following options:
- Use the Java utility `ssl-pinning-tool.jar`
- Use `openssl` commands manually

Both approaches are described in chapters below.

## Prepare Data Using Java Utility

### Supported Java Version

Only Java version 8 is supported at the moment.

### Install Bouncy Castle provider

The Bouncy Castle library is required to be installed in the JRE in order to run the Java utility.

See:
https://github.com/wultra/powerauth-server/wiki/Installing-Bouncy-Castle

### Generate a Signing Key Pair

Before signing the SSL certificate, you will need to generate a new ECDSA key pair and store it in the `keypair.pem` file. You need to store this file securely. This key pair will be used to sign current certificate and all future certificates. If you already signed a certificate before, skip this step and use the previously generated key pair.

The `keypair.pem` contains the private key. The public key can be printed as described in chapter Export public key. 

The following command generates the key pair in PEM format. The key pair is protected by password of your choice. 

```sh
java -jar ssl-pinning-tool.jar keygen -o keypair.pem -p [password]
```

**Store the key pair and private key password safely! You will need it next time you replace SSL certificate to generate new signatures.**

### Prepare Certificate Signature

This command will retrieve the SSL certificate into PEM file:

```sh
openssl s_client -showcerts -connect my.domain.com:443 -servername my.domain.com < /dev/null | openssl x509 -outform PEM > cert.pem
```

Make sure to replace `my.domain.com` in both `-connect` and `-servername` options with your domain name.

This command will generate the SSL certificate signature:

```sh
java -jar ssl-pinning-tool.jar sign -k keypair.pem -c cert.pem -o output.json -p [password]
```

The output file will contain SSL certificate signature:
```json
{
  "name" : "my.domain.com",
  "fingerprint" : "jymEKdgGPv1zSp61CYya5c2fR9fTLe8tKnWF6857iLA=",
  "expires" : 1543322263000,
  "signature" : "MEUCICOs9bb6TIEmRNHCekxn9URADLYuuZnk4aftpVDzdwmWAiEAlU2r9VDEnAWryxvbAsSJfIlCQjKfumdFbZeUKda166w="
}
``` 

Alternatively, you can prepare certificate signature from information about the certificate. This approach is useful when the certificate is not deployed yet.

You need following information:
* Domain common name, e.g. `my.domain.com`
* Certificate fingerprint in HEX format, for example: `8f298429d8063efd734a9eb5098c9ae5cd9f47d7d32def2d2a7585ebce7b88b0`
* SSL certificate expiration time as Unix timestamp, e.g. `1543322263000`

This command will generate the SSL certificate signature:

```sh
java -jar ssl-pinning-tool.jar sign -k keypair.pem -f 8f298429d8063efd734a9eb5098c9ae5cd9f47d7d32def2d2a7585ebce7b88b0 -t 1543322263000 -n my.domain.com -o output.json -p [password]
```

The output file will contain JSON with SSL certificate signature:
```json
{
  "name" : "my.domain.com",
  "fingerprint" : "jymEKdgGPv1zSp61CYya5c2fR9fTLe8tKnWF6857iLA=",
  "expires" : 1543322263000,
  "signature" : "MEUCICOs9bb6TIEmRNHCekxn9URADLYuuZnk4aftpVDzdwmWAiEAlU2r9VDEnAWryxvbAsSJfIlCQjKfumdFbZeUKda166w="
}
``` 

### Export Public Key

Mobile app developers will need the public key from generated key pair in order to be able to verify signatures.

You can convert EC private key to public key and print it:

```sh
java -jar ssl-pinning-tool.jar export -k keypair.pem -p [password]
```

### Troubleshooting

Error: 
```
SEVERE: Failed to load private key, error: unable to read encrypted data: javax.crypto.BadPaddingException: pad block corrupted
```

This error is shown when the private key password is invalid.

Alternatively, you can perform all steps above using `openssl` command.

## Prepare Data Using OpenSSL

In case you have your SSL certificate in a `pem` format, you are able to generate all necessary data using OpenSSL.

### Generate a Key Pair

This command will generate a new ECDSA key pair and store it in the `keypair.pem` file. You need to store this file securely.

```sh
openssl ecparam -name prime256v1 -genkey | openssl pkcs8 -topk8 -v2 aes-128-cbc > keypair.pem
```

**Store the key pair and private key password safely! You will need it next time you replace SSL certificate to generate new signatures.**

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

### Get Certificate Attributes

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

```
TIME=`openssl x509 -noout -dates -inform der -in cert.der | grep notAfter | sed -e 's#notAfter=##'`

if date --version >/dev/null 2>/dev/null; then
  # Linux
  date -d "$TIME" "+%s"
else
  # MacOSX
  date -j -f "%b %d %H:%M:%S %Y %Z" "$TIME" "+%s"  
fi
```

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
openssl dgst -sha256 -sign keypair.pem signature_base_string.txt > sign_raw.txt

# Encode result as Base64
openssl enc -base64 -A < sign_raw.txt > sign.txt
```

### Prepare the JSON with Signature

You need to encode the data into following JSON object:

```json
{
  "fingerprints": [
    {
      "name": "$COMMON_NAME:*.example.com",
      "fingerprint": "$FINGERPRINT_BASE64",
      "expires": "$UNIXTIMESTAMP_EXPIRATION:1535709224",
      "signature": "$SIGNATURE_BASE64"
    }
  ]
}
```

### Export public key

Mobile app developers will need the public key from generated key pair in order to be able to verify signatures.

You can convert EC private key to public key:

```sh
openssl ec -in keypair.pem -pubout
```