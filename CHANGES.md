# Changelog

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

