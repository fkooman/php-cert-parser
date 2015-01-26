<?php

/**
 * Copyright 2013 François Kooman <fkooman@tuxed.net>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace fkooman\X509;

class CertParser
{
    private $strippedCert;
    private $parsedCert;

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

        $pattern = '/-----BEGIN CERTIFICATE-----(.*)-----END CERTIFICATE-----/msU';
        if (1 === preg_match($pattern, $certData, $matches)) {
            $certData = $matches[1];
        }

        // create one long string of the certificate
        $replaceCharacters = array(" ", "\t", "\n", "\r", "\0" , "\x0B");
        $certData = str_replace($replaceCharacters, '', $certData);

        // store this stripped certificate
        $this->strippedCert = $certData;

        // parse the certificate using OpenSSL
        if (!function_exists("openssl_x509_parse")) {
            throw new CertParserException("php openssl extension not available");
        }

        $c = openssl_x509_parse($this->toPEM());
        if (false === $c) {
            throw new CertParserException("unable to parse the certificate");
        }

        $this->parsedCert = $c;
    }

    public function toBase64()
    {
        return $this->strippedCert;
    }

    public function toDer()
    {
        return base64_decode($this->toBase64());
    }

    public function toPem()
    {
        // prepend header and append footer
        $wrapped = wordwrap($this->toBase64(), 64, "\n", true);

        return "-----BEGIN CERTIFICATE-----".PHP_EOL.$wrapped.PHP_EOL."-----END CERTIFICATE-----".PHP_EOL;
    }

    public static function fromFile($fileName)
    {
        $fileData = @file_get_contents($fileName);
        if (false === $fileData) {
            throw new CertParserException("unable to read file");
        }

        return new static($fileData);
    }

    /**
     * Get the UNIX timestamp of when this certificate is valid.
     */
    public function getNotValidBefore()
    {
        if (!array_key_exists("validFrom_time_t", $this->parsedCert)) {
            throw new CertParserException("could not find 'validFrom_time_t' key");
        }

        return $this->parsedCert['validFrom_time_t'];
    }

    /**
     * Get the UNIX timestamp of when this certificate is no longer valid.
     */
    public function getNotValidAfter()
    {
        if (!array_key_exists("validTo_time_t", $this->parsedCert)) {
            throw new CertParserException("could not find 'validTo_time_t' key");
        }

        return $this->parsedCert['validTo_time_t'];
    }

    public function getFingerprint($algorithm = "sha1", $uriSafe = false)
    {
        if (!in_array($algorithm, hash_algos())) {
            throw new CertParserException(sprintf("unsupported algorithm '%s'", $algorithm));
        }

        if ($uriSafe) {
            return rtrim(
                strtr(
                    base64_encode(
                        hash($algorithm, $this->toDer(), true)
                    ),
                    '+/',
                    '-_'
                ),
                '='
            );
        }

        return hash($algorithm, $this->toDer());
    }

    /**
     * Get the common name
     */
    public function getName()
    {
        if (!array_key_exists("name", $this->parsedCert)) {
            throw new CertParserException("could not find 'name' key");
        }

        return $this->parsedCert['name'];
    }

    /**
     * Get the whole subject as string
     *
     * @throws CertParserException
     * @return string
     */
    public function getSubject()
    {
        // @codeCoverageIgnoreStart
        if (!array_key_exists('subject', $this->parsedCert)) {
            throw new CertParserException("could not find 'subject' key");
        }
        // @codeCoverageIgnoreEnd
        return $this->toDistinguishedName($this->parsedCert['subject']);
    }

    /**
     * Get the whole subject as string
     *
     * @throws CertParserException
     * @return string
     */
    public function getIssuer()
    {
        // @codeCoverageIgnoreStart
        if (!array_key_exists('issuer', $this->parsedCert)) {
            throw new CertParserException("could not find 'issuer' key");
        }
        // @codeCoverageIgnoreEnd
        return $this->toDistinguishedName($this->parsedCert['issuer']);
    }

    /**
     * Checks whether current cert is issued by given cert
     *
     * @param CertParser $cert
     *
     * @throws CertParserException
     * @return bool
     */
    public function isIssuedBy(CertParser $cert)
    {
        return $this->getIssuer() === $cert->getSubject();
    }

    /**
     * Returns parsed array data
     *
     * @return array
     */
    private function getCertData()
    {
        return $this->parsedCert;
    }

    /**
     * Transforms the array notification of the distinguished name component to string
     *
     * @param array  $data
     * @param string $separator
     *
     * @return string
     */
    protected function toDistinguishedName(array $data, $separator = ', ')
    {
        $output = array();
        foreach ($data as $key => $item) {
            if (is_array($item)) {
                foreach ($item as $value) {
                    $output [] = "$key=$value";
                }
            } else {
                $output [] = "$key=$item";
            }
        }

        return implode($separator, $output);
    }
}
