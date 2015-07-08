[![Build Status](https://secure.travis-ci.org/fkooman/php-cert-parser.png?branch=master)](http://travis-ci.org/fkooman/php-cert-parser)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/fkooman/php-cert-parser/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/fkooman/php-cert-parser/?branch=master)

# Introduction
This library enables you to parse X.509 certificates in order to be able
to extract some attributes from it and calculate the fingerprint.

# API
For example, to obtain the certificate expiry date from a certificate 
loaded from a file:

    <?php

    use fkooman\X509\CertParser;

    $certParser = CertParser::fromPemFile('certificate.crt');
    echo date('r', $cp->getNotValidAfter()) . PHP_EOL;
    
All API calls:

    public static function fromEncodedDer($encodedDerCert)
    public static function fromEncodedDerFile($filePath)
    public static function fromPem($pemCert)
    public static function fromPemFile($filePath)
    public static function fromDer($derCert)
    public static function fromDerFile($filePath)
    public function getFingerprint($alg = 'sha256')
    public function getName()
    public function getNotValidBefore()
    public function getNotValidAfter()
    public function getIssuer()
    public function getSubject()

# License
Licensed under the Apache License, Version 2.0;

   http://www.apache.org/licenses/LICENSE-2.0

