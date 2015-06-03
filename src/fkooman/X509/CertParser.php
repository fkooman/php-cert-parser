<?php

/**
 * Copyright 2015 François Kooman <fkooman@tuxed.net>.
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

use InvalidArgumentException;
use RuntimeException;

class CertParser
{
    /** @var string */
    private $pemCert;

    private function __construct($pemCert)
    {
        // verify the certificate
        $this->parsePemCert($pemCert);

        $this->pemCert = $pemCert;
    }

    /**
     * Create a new CertParser object from the Base 64 encoded DER, i.e. a
     * base64_encode of a binary string.
     */
    public static function fromEncodedDer($encodedDerCert)
    {
        $pemCert = sprintf(
            '-----BEGIN CERTIFICATE-----%s-----END CERTIFICATE-----',
            PHP_EOL.wordwrap($encodedDerCert, 64, "\n", true).PHP_EOL
        );

        return new self($pemCert);
    }

    public static function fromEncodedDerFile($filePath)
    {
        return self::fromEncodedDer(self::readFile($filePath));
    }

    /**
     * Create a new CertParser object from a PEM formatted certificate.
     */
    public static function fromPem($pemCert)
    {
        return new self($pemCert);
    }

    public static function fromPemFile($filePath)
    {
        return self::fromPem(self::readFile($filePath));
    }

    /**
     * Create a new CertParser object from a DER formatted certificate.
     */
    public static function fromDer($derCert)
    {
        return self::fromEncodedDer(base64_encode($derCert));
    }

    public static function fromDerFile($filePath)
    {
        return self::fromDer(self::readFile($filePath));
    }

    private static function parsePemCert($pemCert)
    {
        $parsedCert = openssl_x509_parse($pemCert);
        if (false === $parsedCert) {
            throw new InvalidArgumentException('OpenSSL was unable to parse the certificate');
        }

        return $parsedCert;
    }

    private static function readFile($filePath)
    {
        $fileData = @file_get_contents($filePath);
        if (false === $fileData) {
            throw new RuntimeException('unable to read certificate file');
        }

        return $fileData;
    }

    /**
     * Get the DER format of the certificate.
     */
    private function toDer()
    {
        $pattern = '/.*-----BEGIN CERTIFICATE-----(.*)-----END CERTIFICATE-----.*/msU';
        $replacement = '${1}';

        $plainPemData = preg_replace($pattern, $replacement, $this->pemCert);
        if (false === $plainPemData) {
            throw new \Exception('foooo!');
            // unable to replace, not a valid PEM?
        }

        // create one long string of the certificate which turns it into an
        // encoded DER cert
        $search = array(' ', "\t", "\n", "\r", "\0" , "\x0B");
        $encodedDerCert = str_replace($search, '', $plainPemData);

        return base64_decode($encodedDerCert);
    }

    /**
     * Get the fingerprint of the certificate.
     *
     * @param string $alg     the algorithm to use, see hash_algos()
     * @param bool   $uriSafe encode the hash according to RFC 6920
     *                        "Naming Things with Hashes" if true
     */
    public function getFingerprint($alg = 'sha256', $uriSafe = false)
    {
        if (!in_array($alg, hash_algos())) {
            throw new RuntimeException(
                sprintf(
                    'unsupported algorithm "%s"',
                    $alg
                )
            );
        }

        if ($uriSafe) {
            return rtrim(
                strtr(
                    base64_encode(
                        hash($alg, $this->toDer(), true)
                    ),
                    '+/',
                    '-_'
                ),
                '='
            );
        }

        return hash($alg, $this->toDer());
    }

    /**
     * Get the common name (CN) of the certificate.
     */
    public function getName()
    {
        $parsedCert = $this->parsePemCert($this->pemCert);
        if (!array_key_exists('name', $parsedCert)) {
            throw new RuntimeException('could not find "name" key');
        }

        return $parsedCert['name'];
    }

    /**
     * Get the issue time of the certificate.
     */
    public function getNotValidBefore()
    {
        $parsedCert = $this->parsePemCert($this->pemCert);
        if (!array_key_exists('validFrom_time_t', $parsedCert)) {
            throw new RuntimeException('could not find "validFrom_time_t" key');
        }

        return $parsedCert['validFrom_time_t'];
    }

    /**
     * Get the expiry time of the certificate.
     */
    public function getNotValidAfter()
    {
        $parsedCert = $this->parsePemCert($this->pemCert);
        if (!array_key_exists('validTo_time_t', $parsedCert)) {
            throw new RuntimeException('could not find "validTo_time_t" key');
        }

        return $parsedCert['validTo_time_t'];
    }

    /**
     * Get the issuer of the certificate as a DN string.
     */
    public function getIssuer()
    {
        $parsedCert = $this->parsePemCert($this->pemCert);
        if (!array_key_exists('issuer', $parsedCert)) {
            throw new RuntimeException('could not find "issuer" key');
        }

        return self::arrayToDn($parsedCert['issuer']);
    }

    /**
     * Get the subject of the certificate as a DN string.
     */
    public function getSubject()
    {
        $parsedCert = $this->parsePemCert($this->pemCert);
        if (!array_key_exists('subject', $parsedCert)) {
            throw new RuntimeException('could not find "subject" key');
        }

        return self::arrayToDn($parsedCert['subject']);
    }

    private static function arrayToDn(array $data, $sep = ', ')
    {
        $keyValue = array();
        foreach ($data as $key => $value) {
            if (is_array($value)) {
                foreach ($value as $v) {
                    $keyValue[] = sprintf('%s=%s', $key, $v);
                }
            } else {
                $keyValue[] = sprintf('%s=%s', $key, $value);
            }
        }

        return implode($sep, $keyValue);
    }
}
