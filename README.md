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

This JSON snippet should be added into the final list of certificate fingerprints. If you have any previous certificate signatures, please merge them with the snipped.
This JSON file will be published on a web server for mobile clients:

```json
{
  "fingerprints": [
    {
      "name" : "my.domain.com",
      "fingerprint" : "jymEKdgGPv1zSp61CYya5c2fR9fTLe8tKnWF6857iLA=",
      "expires" : 1543322263000,
      "signature" : "MEUCICOs9bb6TIEmRNHCekxn9URADLYuuZnk4aftpVDzdwmWAiEAlU2r9VDEnAWryxvbAsSJfIlCQjKfumdFbZeUKda166w="
    }
  ]
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

You can use `openssl` command to download certificate, generate keypair and prepare the certificate signature. The scripts below should work on Linux or Mac OS X.

This command will retrieve the SSL certificate into DER format which is suitable for computing the SHA-256 fingerprint:

```sh
openssl s_client -showcerts -connect my.domain.com:443 -servername my.domain.com < /dev/null | openssl x509 -outform DER > cert.der
```

Make sure to replace `my.domain.com` in both `-connect` and `-servername` options with your domain name.

### Generate a Key Pair

This command will generate a new ECDSA key pair and store it in the `keypair.pem` file. You need to store this file securely.

```sh
openssl ecparam -name prime256v1 -genkey | openssl pkcs8 -topk8 -v2 aes-128-cbc > keypair.pem
```

**Store the key pair and private key password safely! You will need it next time you replace SSL certificate to generate new signatures.**

### Prepare a Certificate Fingerprint

This command converts a server certificate stored in the `cert.der` file to SHA-256 fingerprint in binary form, encoded as Base64 and stored in `fingerprint.txt` file.

```sh
FINGERPRINT_BASE64=`openssl dgst -sha256 -binary < cert.der | openssl enc -base64 -A`
```

### Get Certificate Attributes

In order to compute the signature, you need to have values of certificate common name and expiration timestamp.

To obtain common name, call:

```sh
COMMON_NAME=`openssl x509 -noout -subject -inform der -in cert.der | sed -n '/^subject/s/^.*CN=//p'`
```

To obtain expiration timestamp, call:

```
EXPIRATION_TIME=`openssl x509 -noout -dates -inform der -in cert.der | grep notAfter | sed -e 's#notAfter=##'`

if date --version >/dev/null 2>/dev/null; then
  # Linux
  UNIXTIMESTAMP_EXPIRATION=`date -d "$EXPIRATION_TIME" "+%s"`
else
  # MacOSX
  UNIXTIMESTAMP_EXPIRATION=`date -j -f "%b %d %H:%M:%S %Y %Z" "$EXPIRATION_TIME" "+%s"`  
fi
```

### Sign Certificate Fingerprint

This sequence of commands signs the fingerprint from `fingerprint.txt` with the private key from the provided key pair file `keypair.pem` and stores the result signature as a Base64 encoded file `sign.txt`.

Prepare a signature base string as $COMMON_NAME + '&' + $UNIXTIMESTAMP_EXPIRATION + '&' + $FINGERPRINT:
```sh
echo -n "$COMMON_NAME" > signature_base_string.txt
echo -n "&" >> signature_base_string.txt
echo -n "$UNIXTIMESTAMP_EXPIRATION" >> signature_base_string.txt
echo -n "&" >> signature_base_string.txt
echo -n "$FINGERPRINT_BASE64" >> signature_base_string.txt
```

You can verify the signature base string by printing it:
```sh
cat signature_base_string.txt
```

Sign the signature base string with private key from the key pair:
```sh
openssl dgst -sha256 -sign keypair.pem signature_base_string.txt > signature_raw.txt
```

Encode result as Base64:
```sh
SIGNATURE_BASE64=`openssl enc -base64 -A < signature_raw.txt`
```

### Export public key

Mobile app developers will need the public key from generated key pair in order to be able to verify signatures.

You can convert EC private key to public key:

```sh
openssl ec -in keypair.pem -pubout
```

## Prepare the JSON with Signature

You need to encode the data into JSON. If you have any previous certificate signatures, please merge them with the generated file.
This JSON file will be published on a web server for mobile clients:

```sh
echo "{" > fingerprints.json
echo "  \"fingerprints\": [" >> fingerprints.json
echo "    {" >> fingerprints.json
echo "      \"name\": \"$COMMON_NAME\"," >> fingerprints.json
echo "      \"fingerprint\": \"$FINGERPRINT_BASE64\"," >> fingerprints.json
echo "      \"expires\": $UNIXTIMESTAMP_EXPIRATION," >> fingerprints.json
echo "      \"signature\": \"$SIGNATURE_BASE64\"" >> fingerprints.json
echo "    }" >> fingerprints.json
echo "  ]" >> fingerprints.json
echo "}" >> fingerprints.json
```

You can obtain the JSON output using command:
```sh
cat fingerprints.json
```

### Export public key

Mobile app developers will need the public key from generated key pair in order to be able to verify signatures.

The `openssl` command cannot export ECDSA public key in raw format, so you will need to use our Java utility for the export.

You can convert EC private key to public key and print it:

```sh
java -jar ssl-pinning-tool.jar export -k keypair.pem -p [password]
```
