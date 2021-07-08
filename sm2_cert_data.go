package qtls

import (
	"encoding/asn1"
	"encoding/base64"
	"github.com/xiaotianfork/qtls-go1-15/sm2"
	"github.com/xiaotianfork/qtls-go1-15/x509"
)

const sm2RootCert = `
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            20:b9:ae:6e:9e:e7:8e:68:46:b7:7c:19:2c:5c:31:e7
        Signature Algorithm: SM2-with-SM3
        Issuer: C=CN, ST=HZ, O=ali, OU=ant, CN=www.example.com/emailAddress=client@example.com
        Validity
            Not Before: Apr 14 08:02:52 2020 GMT
            Not After : Apr 12 08:02:52 2030 GMT
        Subject: C=CN, ST=HZ, O=ali, OU=ant, CN=www.example.com/emailAddress=client@example.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:0f:69:9c:d1:cb:58:4b:cc:fa:58:d5:cd:b2:a5:
                    06:3e:eb:44:90:2c:00:39:73:06:5e:26:14:a5:93:
                    23:32:ea:97:dd:01:36:ef:09:6a:40:c2:67:c3:ac:
                    8f:3c:ec:56:8a:f1:d2:ad:d1:f4:e1:83:12:85:ec:
                    ea:de:50:f2:c6
                ASN1 OID: SM2
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                7C:21:1D:07:19:A2:B1:D9:76:1C:B0:95:41:40:6B:BC:36:76:1B:6E
            X509v3 Authority Key Identifier:
                keyid:7C:21:1D:07:19:A2:B1:D9:76:1C:B0:95:41:40:6B:BC:36:76:1B:6E

            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Key Usage: critical
                Digital Signature, Certificate Sign, CRL Sign
    Signature Algorithm: SM2-with-SM3
         30:45:02:21:00:9e:aa:d9:99:60:40:88:a8:a9:07:af:0b:c9:
         4f:06:6b:c0:0e:be:de:40:d1:b4:fd:39:52:42:8c:f8:86:2c:
         b7:02:20:5f:58:9b:07:10:3d:eb:2d:68:47:9d:a0:ce:ec:a0:
         91:20:5f:74:91:fa:cb:60:82:72:14:0f:d8:b2:61:d8:7c
-----BEGIN CERTIFICATE-----
MIICRzCCAe2gAwIBAgIQILmubp7njmhGt3wZLFwx5zAKBggqgRzPVQGDdTBzMQsw
CQYDVQQGEwJDTjELMAkGA1UECAwCSFoxDDAKBgNVBAoMA2FsaTEMMAoGA1UECwwD
YW50MRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20xITAfBgkqhkiG9w0BCQEWEmNs
aWVudEBleGFtcGxlLmNvbTAeFw0yMDA0MTQwODAyNTJaFw0zMDA0MTIwODAyNTJa
MHMxCzAJBgNVBAYTAkNOMQswCQYDVQQIDAJIWjEMMAoGA1UECgwDYWxpMQwwCgYD
VQQLDANhbnQxGDAWBgNVBAMMD3d3dy5leGFtcGxlLmNvbTEhMB8GCSqGSIb3DQEJ
ARYSY2xpZW50QGV4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE
D2mc0ctYS8z6WNXNsqUGPutEkCwAOXMGXiYUpZMjMuqX3QE27wlqQMJnw6yPPOxW
ivHSrdH04YMShezq3lDyxqNjMGEwHQYDVR0OBBYEFHwhHQcZorHZdhywlUFAa7w2
dhtuMB8GA1UdIwQYMBaAFHwhHQcZorHZdhywlUFAa7w2dhtuMA8GA1UdEwEB/wQF
MAMBAf8wDgYDVR0PAQH/BAQDAgGGMAoGCCqBHM9VAYN1A0gAMEUCIQCeqtmZYECI
qKkHrwvJTwZrwA6+3kDRtP05UkKM+IYstwIgX1ibBxA96y1oR52gzuygkSBfdJH6
y2CCchQP2LJh2Hw=
-----END CERTIFICATE-----
`

var sm2RootCertByte = base64ToByte("MIICRzCCAe2gAwIBAgIQILmubp7njmhGt3wZLFwx5zAKBggqgRzPVQGDdTBzMQsw\nCQYDVQQGEwJDTjELMAkGA1UECAwCSFoxDDAKBgNVBAoMA2FsaTEMMAoGA1UECwwD\nYW50MRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20xITAfBgkqhkiG9w0BCQEWEmNs\naWVudEBleGFtcGxlLmNvbTAeFw0yMDA0MTQwODAyNTJaFw0zMDA0MTIwODAyNTJa\nMHMxCzAJBgNVBAYTAkNOMQswCQYDVQQIDAJIWjEMMAoGA1UECgwDYWxpMQwwCgYD\nVQQLDANhbnQxGDAWBgNVBAMMD3d3dy5leGFtcGxlLmNvbTEhMB8GCSqGSIb3DQEJ\nARYSY2xpZW50QGV4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE\nD2mc0ctYS8z6WNXNsqUGPutEkCwAOXMGXiYUpZMjMuqX3QE27wlqQMJnw6yPPOxW\nivHSrdH04YMShezq3lDyxqNjMGEwHQYDVR0OBBYEFHwhHQcZorHZdhywlUFAa7w2\ndhtuMB8GA1UdIwQYMBaAFHwhHQcZorHZdhywlUFAa7w2dhtuMA8GA1UdEwEB/wQF\nMAMBAf8wDgYDVR0PAQH/BAQDAgGGMAoGCCqBHM9VAYN1A0gAMEUCIQCeqtmZYECI\nqKkHrwvJTwZrwA6+3kDRtP05UkKM+IYstwIgX1ibBxA96y1oR52gzuygkSBfdJH6\ny2CCchQP2LJh2Hw=")

const sm2RootKey = `-----BEGIN EC PARAMETERS-----
BggqgRzPVQGCLQ==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIKd8IpFgNnD9lTIr1eE8dD72HNTkTA2cSBSdRo+LCuuToAoGCCqBHM9V
AYItoUQDQgAED2mc0ctYS8z6WNXNsqUGPutEkCwAOXMGXiYUpZMjMuqX3QE27wlq
QMJnw6yPPOxWivHSrdH04YMShezq3lDyxg==
-----END EC PRIVATE KEY-----
`
const sm2intermediateCert = `Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            20:b9:ae:6e:9e:e7:8e:68:46:b7:7c:19:2c:5c:31:e8
        Signature Algorithm: SM2-with-SM3
        Issuer: C=CN, ST=HZ, O=ali, OU=ant, CN=www.example.com/emailAddress=client@example.com
        Validity
            Not Before: Apr 14 08:11:01 2020 GMT
            Not After : Apr 12 08:11:01 2030 GMT
        Subject: C=CN, ST=HZ, O=ali, OU=ant, CN=www.middle.com/emailAddress=test@test.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:b7:11:be:0e:2c:8d:37:d7:09:cc:d8:f9:4c:b7:
                    70:d7:5a:7d:41:e1:6e:aa:44:98:e1:a9:35:20:88:
                    f5:58:a6:4e:38:23:48:8a:d8:0f:26:a7:17:f1:70:
                    74:d3:aa:e4:59:d1:56:8e:55:d1:5f:bc:dc:68:ea:
                    dc:fa:6c:59:13
                ASN1 OID: SM2
        X509v3 extensions:
            X509v3 Subject Key Identifier: 
                71:50:68:57:73:2A:22:D6:E6:D2:92:0B:3A:09:C5:56:58:00:61:5E
            X509v3 Authority Key Identifier: 
                keyid:7C:21:1D:07:19:A2:B1:D9:76:1C:B0:95:41:40:6B:BC:36:76:1B:6E

            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Key Usage: critical
                Digital Signature, Certificate Sign, CRL Sign
    Signature Algorithm: SM2-with-SM3
         30:44:02:20:6e:2e:e8:37:0f:b6:43:e8:a1:7d:b3:a7:b9:61:
         da:5a:1c:ff:c6:83:02:ce:b9:5f:3e:3d:11:04:98:af:85:28:
         02:20:78:bb:df:5d:e2:c7:22:1a:9a:41:ee:07:f0:3f:3b:6c:
         ef:be:20:cd:24:ae:06:3a:57:6a:94:fc:9a:c2:13:83
-----BEGIN CERTIFICATE-----
MIICQzCCAeqgAwIBAgIQILmubp7njmhGt3wZLFwx6DAKBggqgRzPVQGDdTBzMQsw
CQYDVQQGEwJDTjELMAkGA1UECAwCSFoxDDAKBgNVBAoMA2FsaTEMMAoGA1UECwwD
YW50MRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20xITAfBgkqhkiG9w0BCQEWEmNs
aWVudEBleGFtcGxlLmNvbTAeFw0yMDA0MTQwODExMDFaFw0zMDA0MTIwODExMDFa
MG0xCzAJBgNVBAYTAkNOMQswCQYDVQQIDAJIWjEMMAoGA1UECgwDYWxpMQwwCgYD
VQQLDANhbnQxFzAVBgNVBAMMDnd3dy5taWRkbGUuY29tMRwwGgYJKoZIhvcNAQkB
Fg10ZXN0QHRlc3QuY29tMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEtxG+DiyN
N9cJzNj5TLdw11p9QeFuqkSY4ak1IIj1WKZOOCNIitgPJqcX8XB006rkWdFWjlXR
X7zcaOrc+mxZE6NmMGQwHQYDVR0OBBYEFHFQaFdzKiLW5tKSCzoJxVZYAGFeMB8G
A1UdIwQYMBaAFHwhHQcZorHZdhywlUFAa7w2dhtuMBIGA1UdEwEB/wQIMAYBAf8C
AQAwDgYDVR0PAQH/BAQDAgGGMAoGCCqBHM9VAYN1A0cAMEQCIG4u6DcPtkPooX2z
p7lh2loc/8aDAs65Xz49EQSYr4UoAiB4u99d4sciGppB7gfwPzts774gzSSuBjpX
apT8msITgw==
-----END CERTIFICATE-----
`

var sm2IntermediateCertByte = base64ToByte("MIICQzCCAeqgAwIBAgIQILmubp7njmhGt3wZLFwx6DAKBggqgRzPVQGDdTBzMQsw\nCQYDVQQGEwJDTjELMAkGA1UECAwCSFoxDDAKBgNVBAoMA2FsaTEMMAoGA1UECwwD\nYW50MRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20xITAfBgkqhkiG9w0BCQEWEmNs\naWVudEBleGFtcGxlLmNvbTAeFw0yMDA0MTQwODExMDFaFw0zMDA0MTIwODExMDFa\nMG0xCzAJBgNVBAYTAkNOMQswCQYDVQQIDAJIWjEMMAoGA1UECgwDYWxpMQwwCgYD\nVQQLDANhbnQxFzAVBgNVBAMMDnd3dy5taWRkbGUuY29tMRwwGgYJKoZIhvcNAQkB\nFg10ZXN0QHRlc3QuY29tMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEtxG+DiyN\nN9cJzNj5TLdw11p9QeFuqkSY4ak1IIj1WKZOOCNIitgPJqcX8XB006rkWdFWjlXR\nX7zcaOrc+mxZE6NmMGQwHQYDVR0OBBYEFHFQaFdzKiLW5tKSCzoJxVZYAGFeMB8G\nA1UdIwQYMBaAFHwhHQcZorHZdhywlUFAa7w2dhtuMBIGA1UdEwEB/wQIMAYBAf8C\nAQAwDgYDVR0PAQH/BAQDAgGGMAoGCCqBHM9VAYN1A0cAMEQCIG4u6DcPtkPooX2z\np7lh2loc/8aDAs65Xz49EQSYr4UoAiB4u99d4sciGppB7gfwPzts774gzSSuBjpX\napT8msITgw==")

const sm2IntermediateKey = `-----BEGIN EC PARAMETERS-----
BggqgRzPVQGCLQ==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFB3gBTaAJYNNKkY4zDMxmgPCJuSt3G2WDO2x0I8nXzVoAoGCCqBHM9V
AYItoUQDQgAEtxG+DiyNN9cJzNj5TLdw11p9QeFuqkSY4ak1IIj1WKZOOCNIitgP
JqcX8XB006rkWdFWjlXRX7zcaOrc+mxZEw==
-----END EC PRIVATE KEY-----
`

var sm2IntermediatePrivateKeyByte = ParseSm2PrivateKey("MHcCAQEEIFB3gBTaAJYNNKkY4zDMxmgPCJuSt3G2WDO2x0I8nXzVoAoGCCqBHM9V\nAYItoUQDQgAEtxG+DiyNN9cJzNj5TLdw11p9QeFuqkSY4ak1IIj1WKZOOCNIitgP\nJqcX8XB006rkWdFWjlXRX7zcaOrc+mxZEw==")

const sm2LeafCert = `Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            20:b9:ae:6e:9e:e7:8e:68:46:b7:7c:19:2c:5c:31:ea
        Signature Algorithm: SM2-with-SM3
        Issuer: C=CN, ST=HZ, O=ali, OU=ant, CN=www.middle.com/emailAddress=test@test.com
        Validity
            Not Before: Apr 14 09:07:39 2020 GMT
            Not After : Apr 12 09:07:39 2030 GMT
        Subject: C=CN, ST=HZ, O=ali, OU=ant, CN=*.alipay.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:31:b8:86:8c:1c:64:0e:b0:b5:af:0b:95:94:80:
                    bf:e9:f6:c6:76:76:8a:c6:3d:bf:2e:4b:fd:11:c3:
                    8b:2a:fd:d6:16:e1:62:d5:e6:9e:52:f4:12:90:d7:
                    11:31:d6:80:8b:1a:4c:f9:12:90:f8:2a:7a:67:7b:
                    33:25:4a:f4:8d
                ASN1 OID: SM2
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            Netscape Cert Type: 
                SSL Server
            Netscape Comment: 
                OpenSSL Generated Server Certificate
            X509v3 Subject Key Identifier: 
                29:B0:1B:EF:D2:90:55:4A:11:8A:8F:62:1B:DC:C2:EA:0A:BE:D8:F0
            X509v3 Authority Key Identifier: 
                keyid:71:50:68:57:73:2A:22:D6:E6:D2:92:0B:3A:09:C5:56:58:00:61:5E
                DirName:/C=CN/ST=HZ/O=ali/OU=ant/CN=www.example.com/emailAddress=client@example.com
                serial:20:B9:AE:6E:9E:E7:8E:68:46:B7:7C:19:2C:5C:31:E8

            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Subject Alternative Name: 
                DNS:alipay.com, DNS:*.alipay.com
    Signature Algorithm: SM2-with-SM3
         30:46:02:21:00:9a:e3:02:b9:92:9a:17:7c:d5:61:cd:53:e8:
         31:86:8b:4f:a1:98:cb:99:8e:91:fb:bb:39:f0:aa:2c:7b:18:
         9b:02:21:00:8e:8c:1f:e2:1b:e5:b1:3a:f5:33:ff:fb:7f:fd:
         1b:b5:42:75:62:bc:36:82:11:05:e4:5b:67:57:c9:7f:9f:5a
-----BEGIN CERTIFICATE-----
MIIDKjCCAs+gAwIBAgIQILmubp7njmhGt3wZLFwx6jAKBggqgRzPVQGDdTBtMQsw
CQYDVQQGEwJDTjELMAkGA1UECAwCSFoxDDAKBgNVBAoMA2FsaTEMMAoGA1UECwwD
YW50MRcwFQYDVQQDDA53d3cubWlkZGxlLmNvbTEcMBoGCSqGSIb3DQEJARYNdGVz
dEB0ZXN0LmNvbTAeFw0yMDA0MTQwOTA3MzlaFw0zMDA0MTIwOTA3MzlaME0xCzAJ
BgNVBAYTAkNOMQswCQYDVQQIDAJIWjEMMAoGA1UECgwDYWxpMQwwCgYDVQQLDANh
bnQxFTATBgNVBAMMDCouYWxpcGF5LmNvbTBZMBMGByqGSM49AgEGCCqBHM9VAYIt
A0IABDG4howcZA6wta8LlZSAv+n2xnZ2isY9vy5L/RHDiyr91hbhYtXmnlL0EpDX
ETHWgIsaTPkSkPgqemd7MyVK9I2jggFvMIIBazAJBgNVHRMEAjAAMBEGCWCGSAGG
+EIBAQQEAwIGQDAzBglghkgBhvhCAQ0EJhYkT3BlblNTTCBHZW5lcmF0ZWQgU2Vy
dmVyIENlcnRpZmljYXRlMB0GA1UdDgQWBBQpsBvv0pBVShGKj2Ib3MLqCr7Y8DCB
rAYDVR0jBIGkMIGhgBRxUGhXcyoi1ubSkgs6CcVWWABhXqF3pHUwczELMAkGA1UE
BhMCQ04xCzAJBgNVBAgMAkhaMQwwCgYDVQQKDANhbGkxDDAKBgNVBAsMA2FudDEY
MBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMSEwHwYJKoZIhvcNAQkBFhJjbGllbnRA
ZXhhbXBsZS5jb22CECC5rm6e545oRrd8GSxcMegwDgYDVR0PAQH/BAQDAgWgMBMG
A1UdJQQMMAoGCCsGAQUFBwMBMCMGA1UdEQQcMBqCCmFsaXBheS5jb22CDCouYWxp
cGF5LmNvbTAKBggqgRzPVQGDdQNJADBGAiEAmuMCuZKaF3zVYc1T6DGGi0+hmMuZ
jpH7uznwqix7GJsCIQCOjB/iG+WxOvUz//t//Ru1QnVivDaCEQXkW2dXyX+fWg==
-----END CERTIFICATE-----
`
const sm2LeafKey = `-----BEGIN EC PARAMETERS-----
BggqgRzPVQGCLQ==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJ0I4yR5ezlVWygUi7+NNipNJSBqUjaCopitIJMU1nlSoAoGCCqBHM9V
AYItoUQDQgAEMbiGjBxkDrC1rwuVlIC/6fbGdnaKxj2/Lkv9EcOLKv3WFuFi1eae
UvQSkNcRMdaAixpM+RKQ+Cp6Z3szJUr0jQ==
-----END EC PRIVATE KEY-----
`

var sm2LeafCertByte = base64ToByte("MIIDKjCCAs+gAwIBAgIQILmubp7njmhGt3wZLFwx6jAKBggqgRzPVQGDdTBtMQsw\nCQYDVQQGEwJDTjELMAkGA1UECAwCSFoxDDAKBgNVBAoMA2FsaTEMMAoGA1UECwwD\nYW50MRcwFQYDVQQDDA53d3cubWlkZGxlLmNvbTEcMBoGCSqGSIb3DQEJARYNdGVz\ndEB0ZXN0LmNvbTAeFw0yMDA0MTQwOTA3MzlaFw0zMDA0MTIwOTA3MzlaME0xCzAJ\nBgNVBAYTAkNOMQswCQYDVQQIDAJIWjEMMAoGA1UECgwDYWxpMQwwCgYDVQQLDANh\nbnQxFTATBgNVBAMMDCouYWxpcGF5LmNvbTBZMBMGByqGSM49AgEGCCqBHM9VAYIt\nA0IABDG4howcZA6wta8LlZSAv+n2xnZ2isY9vy5L/RHDiyr91hbhYtXmnlL0EpDX\nETHWgIsaTPkSkPgqemd7MyVK9I2jggFvMIIBazAJBgNVHRMEAjAAMBEGCWCGSAGG\n+EIBAQQEAwIGQDAzBglghkgBhvhCAQ0EJhYkT3BlblNTTCBHZW5lcmF0ZWQgU2Vy\ndmVyIENlcnRpZmljYXRlMB0GA1UdDgQWBBQpsBvv0pBVShGKj2Ib3MLqCr7Y8DCB\nrAYDVR0jBIGkMIGhgBRxUGhXcyoi1ubSkgs6CcVWWABhXqF3pHUwczELMAkGA1UE\nBhMCQ04xCzAJBgNVBAgMAkhaMQwwCgYDVQQKDANhbGkxDDAKBgNVBAsMA2FudDEY\nMBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMSEwHwYJKoZIhvcNAQkBFhJjbGllbnRA\nZXhhbXBsZS5jb22CECC5rm6e545oRrd8GSxcMegwDgYDVR0PAQH/BAQDAgWgMBMG\nA1UdJQQMMAoGCCsGAQUFBwMBMCMGA1UdEQQcMBqCCmFsaXBheS5jb22CDCouYWxp\ncGF5LmNvbTAKBggqgRzPVQGDdQNJADBGAiEAmuMCuZKaF3zVYc1T6DGGi0+hmMuZ\njpH7uznwqix7GJsCIQCOjB/iG+WxOvUz//t//Ru1QnVivDaCEQXkW2dXyX+fWg==")

func base64ToByte(cert string) []byte {
	bytes, err := base64.StdEncoding.DecodeString(cert)
	if err != nil {
		panic(err)
	}
	return bytes
}

type sm2PrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

func ParseSm2PrivateKey(privateKeyString string) *sm2.PrivateKey {
	daBuf := base64ToByte(privateKeyString)
	key, err := x509.ParseSm2PrivateKey(daBuf)
	if err != nil {
		panic(err)
	}
	return key
}

var sm2LeafPrivateKeyByte = ParseSm2PrivateKey("MHcCAQEEIJ0I4yR5ezlVWygUi7+NNipNJSBqUjaCopitIJMU1nlSoAoGCCqBHM9V\nAYItoUQDQgAEMbiGjBxkDrC1rwuVlIC/6fbGdnaKxj2/Lkv9EcOLKv3WFuFi1eae\nUvQSkNcRMdaAixpM+RKQ+Cp6Z3szJUr0jQ==")
