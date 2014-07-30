# Introduction
This library enables you to parse X.509 certificates in order to be able
to extract some attributes from it.

Currently the API is very limited and will be expanded based on actual 
needs API consumers.

[![Build Status](https://secure.travis-ci.org/fkooman/php-cert-parser.png?branch=master)](http://travis-ci.org/fkooman/php-cert-parser)

# API
For example, to obtain the certificate expiry date from a certificate 
loaded from a file:

    <?php

    use fkooman\X509\CertParser;
    use fkooman\X509\CertParserException;

    try { 
        $cp = CertParser::fromFile("certificate.pem");
        echo date("r", $cp->getNotValidAfter()) . PHP_EOL;
    } catch (CertParserException $e) {
        echo $e->getMessage();
    }

Or from a string:

    try { 
        $cp = new CertParser("MIIDyzCC...CYkxLaPI");
        echo date("r", $cp->getNotValidAfter()) . PHP_EOL;
    } catch (CertParserException $e) {
        echo $e->getMessage();
    }

All API calls:

* `getFingerprint($algorithm = "sha1")` - get the fingerprint of the 
  certificate, by default `sha1`. See `hash_algos()` in the PHP manual to
  figure out supported hash algorithms
* `getName()` - get the subject DN
* `notValidBefore()` - get the UNIX timestamp from which the certificate is 
  valid
* `notValidAfter()` - get the UNIX timestamp after which the certificate is no 
  longer valid
* `toDer()` - get the DER encoded certificate
* `toPem()` - get the certificate as PEM
* `toBase64()` - get the base64 encoded DER certificate (PEM without headers on 
  one line)

# License
Licensed under the Apache License, Version 2.0;

   http://www.apache.org/licenses/LICENSE-2.0

