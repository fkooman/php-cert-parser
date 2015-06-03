# Changelog

## 0.2.0
- remove `CertParserException`, use `RuntimeException` and 
  `InvalidArgumentException` instead
- change default fingerprint algorithm to SHA-256

## 0.1.8
- add RPM spec files
- add COPYING file

## 0.1.7
- support URL safe fingerprint encoding by specifying `true` as second
  parameter to `getFingerprint()`, see
  [http://tools.ietf.org/html/draft-hallambaker-digesturi-02](http://tools.ietf.org/html/draft-hallambaker-digesturi-02)

## 0.1.6
- also support PEM files containing some text before the actual certificate
- rename package to `fkooman/cert-parser`

## 0.1.5
- add contribution from Ulrich Kautz to make it possible to check whether a 
  certificate is issued by another certificate (WEAK comparison by comparing
  the DN from the issuer and the subject, no certificate verification!)
 
## 0.1.4
- add Travis CI configuration script

## 0.1.3
- actually make algorithm choosing work, still had SHA1 hard coded
- add additional tests for getFingerprint()

## 0.1.2
- give `getFingerprint` a parameter to specify the hashing algorithm. By default
  it is still `sha1`
- add Apache 2.0 license to the code

## 0.1.1
- add `toDer()`, `toPem()`, `toBase64()` methods

## 0.1.0
- initial release

