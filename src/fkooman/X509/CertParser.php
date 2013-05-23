<?php

namespace fkooman\X509;

class CertParser
{

    private $_c;
    private $_fingerPrint;

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

        if (!function_exists("openssl_x509_parse")) {
            throw new CertParserException("php openssl extension not available");
        }

        // normalize the certificate to be able to calculate fingerprint
        $certData = preg_replace('/\-+BEGIN CERTIFICATE\-+/', '', $certData);
        $certData = preg_replace('/\-+END CERTIFICATE\-+/', '', $certData);

        // replace all new lines and other space symbols with nothing
        $replaceCharacters = array(" ", "\t", "\n", "\r", "\0" , "\x0B");
        $certData = str_replace($replaceCharacters, '', $certData);

        $this->_fingerPrint = sha1(base64_decode($certData));

        // maximum 64 characters line length
        $certData = wordwrap($certData, 64, "\n", TRUE);

        // prepend header and append footer
        $certData = "-----BEGIN CERTIFICATE-----" . PHP_EOL . $certData . PHP_EOL . "-----END CERTIFICATE-----" . PHP_EOL;

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
     * Get the UNIX timestamp of when this certificate is valid.
     */
    public function getNotValidBefore()
    {
        if (!array_key_exists("validFrom_time_t", $this->_c)) {
            throw new CertParserException("could not find 'validFrom_time_t' key");
        }

        return $this->_c['validFrom_time_t'];
    }

    /**
     * Get the UNIX timestamp of when this certificate is no longer valid.
     */
    public function getNotValidAfter()
    {
        if (!array_key_exists("validTo_time_t", $this->_c)) {
            throw new CertParserException("could not find 'validTo_time_t' key");
        }

        return $this->_c['validTo_time_t'];
    }

    public function getFingerprint()
    {
        return $this->_fingerPrint;
    }

    public function getCertificateData()
    {
        return $this->_c;
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
