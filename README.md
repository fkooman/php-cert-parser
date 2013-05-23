# Introduction
This library enables you to parse X.509 certificates in order to be able
to extract some attributes from it.

Currently the API is very limited and will be expanded based on actual 
needs API consumers.

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

Other API calls:

* `getFingerprint()` - get the SHA1 fingerprint of the certificate
* `getName()` - get the subject DN

