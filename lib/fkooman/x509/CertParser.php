<?php

namespace fkooman\x509;

class CertParser
{

    private $_c;

    /**
     * Construct the CertParser object.
     *
     * @param certData the PEM or base64 encoded DER certificate data
     */
    public function __construct($certData)
    {
        if (!is_string($certData)) {
            throw new CertParserException("input should be string");
        }

        if (0 !== strpos($certData, "-----BEGIN CERTIFICATE-----")) {
            // assume certificate is not in proper PEM format

            // replace all new lines and other space symbols with nothing
            $replaceCharacters = array(" ", "\t", "\n", "\r", "\0" , "\x0B");
            $certData = str_replace($replaceCharacters, "", $certData);

            // normalize to maximum 64 bytes line length
            $certData = wordwrap($certData, 64, "\n", TRUE);

            // prepend header and append footer
            $certData = "-----BEGIN CERTIFICATE-----" . "\n" . $certData . PHP_EOL . "-----END CERTIFICATE-----" . PHP_EOL;
        }

        if (!function_exists("openssl_x509_parse")) {
            throw new CertParserException("php openssl extension not available");
        }

        $this->_c = openssl_x509_parse($certData);
        if (FALSE === $this->_c) {
            throw new CertParserException("unable to parse the certificate");
        }
    }

    public static function fromFile($fileName)
    {
        $fileData = @file_get_contents($fileName);
        if (FALSE === $fileData) {
            throw new CertParserException("unable to read file");
        }

        return new static($fileData);
    }

    /**
     * Get the expiry (unix) timestamp
     */
    public function getExpiry()
    {
        if (!array_key_exists("validTo_time_t", $this->_c)) {
            throw new CertParserException("could not find 'validTo_time_t' key");
        }

        return $this->_c['validTo_time_t'];
    }

    /**
     * Get the common name
     */
    public function getName()
    {
        if (!array_key_exists("name", $this->_c)) {
            throw new CertParserException("could not find 'name' key");
        }

        return $this->_c['name'];
    }

}
