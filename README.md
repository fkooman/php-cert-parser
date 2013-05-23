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
        $cp = \fkooman\x509\CertParser::fromFile("certificate.pem");
        echo date("r", $cp->getExpiry()) . PHP_EOL;
    } catch (\fkooman\x509\CertParserException $e) {
        echo $e->getMessage();
    }

Or from a string:

    try { 
        $cp = new \fkooman\x509\CertParser("MIIDyzCC...CYkxLaPI");
        echo date("r", $cp->getExpiry()) . PHP_EOL;
    } catch (\fkooman\x509\CertParserException $e) {
        echo $e->getMessage();
    }

