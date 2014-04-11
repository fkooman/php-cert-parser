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

    try {
        $cp = \fkooman\X509\CertParser::fromFile("certificate.pem");
        echo date("r", $cp->getNotValidAfter()) . PHP_EOL;
    } catch (\fkooman\X509\CertParserException $e) {
        echo $e->getMessage();
    }

Or from a string:

    try {
        $cp = new \fkooman\X509\CertParser("MIIDyzCC...CYkxLaPI");
        echo date("r", $cp->getNotValidAfter()) . PHP_EOL;
    } catch (\fkooman\X509\CertParserException $e) {
        echo $e->getMessage();
    }

Check if one cert is issued by another one:

    <?php
    try {
        $cert1 = \fkooman\X509\CertParser::fromFile("certificate1.pem");
        $cert2 = \fkooman\X509\CertParser::fromFile("certificate2.pem");
        if ($cert1->isIssuedBy($cert2)) {
            echo $cert1->getName() . " is issued by " . $cert2->getName(). PHP_EOL;
        }
    } catch (\fkooman\X509\CertParserException $e) {
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
* `getSubject()` - get the full distinguished name of the subject as string
* `getIssuer()` - get the full distinguished name of the issuer as string
* `isIssuedBy(CertParser $cert)` - checks if current cert is issued by given cert


# License
Licensed under the Apache License, Version 2.0;

   http://www.apache.org/licenses/LICENSE-2.0

