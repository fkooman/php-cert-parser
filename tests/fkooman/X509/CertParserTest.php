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

class CertParserTest extends \PHPUnit_Framework_TestCase
{

    public function testCert()
    {
        $dataDir = dirname(dirname(__DIR__)) . DIRECTORY_SEPARATOR . "data";
        $testFiles = array ("1.pem");

        foreach ($testFiles as $t) {
            $c = CertParser::fromFile($dataDir . DIRECTORY_SEPARATOR . $t);
            $this->assertEquals(1295864337, $c->getNotValidBefore());
            $this->assertEquals(1611397137, $c->getNotValidAfter());
            $this->assertEquals(
                '/C=NL/ST=Utrecht/L=Utrecht/O=SURFnet B.V./OU=SURFconext/CN=engine.surfconext.nl',
                $c->getName()
            );
            $this->assertEquals(
                'a36aac83b9a552b3dc724bfc0d7bba6283af5f8e',
                $c->getFingerprint("sha1")
            );
            $this->assertEquals(
                '47659a13647d2befbbd431b0580079c4203c3897dff90e92578cb9a235d67407',
                $c->getFingerprint("sha256")
            );

            $base64 = $c->toBase64();
            $d = new CertParser($base64);
            $this->assertEquals('a36aac83b9a552b3dc724bfc0d7bba6283af5f8e', $d->getFingerprint("sha1"));
        }
    }

    /**
     * @expectedException \fkooman\X509\CertParserException
     * @expectedExceptionMessage unable to parse the certificate
     */
    public function testBrokenData()
    {
        $c = new CertParser("foo");
    }

    /**
     * @expectedException \fkooman\X509\CertParserException
     * @expectedExceptionMessage unsupported algorithm 'foo'
     */
    public function testUnsupportedAlgorithm()
    {
        $testFile = dirname(dirname(__DIR__)) . DIRECTORY_SEPARATOR . "data" . DIRECTORY_SEPARATOR . "1.pem";
        $c = CertParser::fromFile($testFile);
        $c->getFingerprint("foo");
    }

    public function testSubjectIsExtractedAndFormatted()
    {
        $certParser = $this->generateCertParser('2');
        $result     = $certParser->getSubject();
        $this->assertSame('C=DE, ST=Berlin, L=Berlin, O=FooBar Inc, OU=Testing, CN=foobar.tld, emailAddress=baz@foobar.tld', $result);
    }

    public function testIssuerIsExtractedAndFormatted()
    {
        $certParser = $this->generateCertParser('2');
        $result     = $certParser->getIssuer();
        $this->assertSame('C=DE, ST=Berlin, L=Berlin, O=FooBar Inc, OU=Testing CA, CN=foobar.tld, emailAddress=baz@foobar.tld', $result);
    }

    public function testMultipleComponentsInDistinguishedName()
    {
        if (PHP_VERSION <= '5.4.0') {
            $this->markTestSkipped('Works only with PHP >= 5.4');
        } else {
            $certParser = $this->generateCertParser('2-multi');
            $result     = $certParser->getSubject();
            $this->assertSame('C=DE, ST=Berlin, L=Berlin, O=FooBar Inc, OU=Testing Multi, OU=Foo, CN=multi.foobar.tld, emailAddress=baz@foobar.tld', $result);
        }
    }

    public function testValidSigningChainIsCorrectlyRecognized()
    {
        $cert = $this->generateCertParser('2');
        $ca   = $this->generateCertParser('2-ca');
        $this->assertTrue($cert->isIssuedBy($ca));
    }

    public function testInvalidSigningChainIsCorrectlyRecognized()
    {
        $cert = $this->generateCertParser('2');
        $ca   = $this->generateCertParser('2-ca');
        $this->assertFalse($ca->isIssuedBy($cert));
    }

    protected function generateCertParser($name = '1')
    {
        $testFile = dirname(dirname(__DIR__)) . DIRECTORY_SEPARATOR . "data" . DIRECTORY_SEPARATOR . "{$name}.pem";
        $c = CertParser::fromFile($testFile);

        return $c;
    }

}
