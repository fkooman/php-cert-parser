<?php

/**
 * Copyright 2013 François Kooman <fkooman@tuxed.net>.
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

use PHPUnit_Framework_TestCase;

class CertParserTest extends PHPUnit_Framework_TestCase
{
    public static function getFilePath($fileName)
    {
        $filePath = dirname(dirname(__DIR__)).'/data/';

        return $filePath.$fileName;
    }

    public function testFromPemFile()
    {
        $certParser = CertParser::fromPemFile(self::getFilePath('1.pem'));
        $this->assertEquals(1295864337, $certParser->getNotValidBefore());
        $this->assertEquals(1611397137, $certParser->getNotValidAfter());
        $this->assertEquals('/C=NL/ST=Utrecht/L=Utrecht/O=SURFnet B.V./OU=SURFconext/CN=engine.surfconext.nl', $certParser->getName());
        $this->assertEquals('47659a13647d2befbbd431b0580079c4203c3897dff90e92578cb9a235d67407', $certParser->getFingerprint());
        $this->assertEquals('C=NL, ST=Utrecht, L=Utrecht, O=SURFnet B.V., OU=SURFconext, CN=engine.surfconext.nl', $certParser->getIssuer());
        $this->assertEquals('C=NL, ST=Utrecht, L=Utrecht, O=SURFnet B.V., OU=SURFconext, CN=engine.surfconext.nl', $certParser->getSubject());
        $this->assertEquals('R2WaE2R9K--71DGwWAB5xCA8OJff-Q6SV4y5ojXWdAc', $certParser->getFingerPrint('sha256', true));
    }

    public function testFromDerFile()
    {
        $certParser = CertParser::fromDerFile(self::getFilePath('1.der'));
        $this->assertEquals(1295864337, $certParser->getNotValidBefore());
        $this->assertEquals(1611397137, $certParser->getNotValidAfter());
        $this->assertEquals('/C=NL/ST=Utrecht/L=Utrecht/O=SURFnet B.V./OU=SURFconext/CN=engine.surfconext.nl', $certParser->getName());
        $this->assertEquals('47659a13647d2befbbd431b0580079c4203c3897dff90e92578cb9a235d67407', $certParser->getFingerprint());
        $this->assertEquals('C=NL, ST=Utrecht, L=Utrecht, O=SURFnet B.V., OU=SURFconext, CN=engine.surfconext.nl', $certParser->getIssuer());
        $this->assertEquals('C=NL, ST=Utrecht, L=Utrecht, O=SURFnet B.V., OU=SURFconext, CN=engine.surfconext.nl', $certParser->getSubject());
    }

    public function testFromEncodedDerFile()
    {
        $certParser = CertParser::fromEncodedDerFile(self::getFilePath('1_flat.pem'));
        $this->assertEquals(1295864337, $certParser->getNotValidBefore());
        $this->assertEquals(1611397137, $certParser->getNotValidAfter());
        $this->assertEquals('/C=NL/ST=Utrecht/L=Utrecht/O=SURFnet B.V./OU=SURFconext/CN=engine.surfconext.nl', $certParser->getName());
        $this->assertEquals('47659a13647d2befbbd431b0580079c4203c3897dff90e92578cb9a235d67407', $certParser->getFingerprint());
        $this->assertEquals('C=NL, ST=Utrecht, L=Utrecht, O=SURFnet B.V., OU=SURFconext, CN=engine.surfconext.nl', $certParser->getIssuer());
        $this->assertEquals('C=NL, ST=Utrecht, L=Utrecht, O=SURFnet B.V., OU=SURFconext, CN=engine.surfconext.nl', $certParser->getSubject());
    }

    public function testFromPemFileWithGarbageHeader()
    {
        $certParser = CertParser::fromPemFile(self::getFilePath('garbage-header.pem'));
        $this->assertEquals('e16f4100e1562ac8b75fb21b1b89875d40ca50ba', $certParser->getFingerPrint('sha1'));
    }

    /**
     * @expectedException InvalidArgumentException
     * @expectedExceptionMessage unable to parse the certificate
     */
    public function testBrokenData()
    {
        $certParser = CertParser::fromPem('foo');
    }

    /**
     * @expectedException RuntimeException
     * @expectedExceptionMessage unsupported algorithm "foo"
     */
    public function testUnsupportedAlgorithm()
    {
        $certParser = CertParser::fromPemFile(self::getFilePath('1.pem'));
        $certParser->getFingerprint('foo');
    }

    public function testSubjectIsExtractedAndFormatted()
    {
        $certParser = CertParser::fromPemFile(self::getFilePath('2.pem'));
        $this->assertSame('C=DE, ST=Berlin, L=Berlin, O=FooBar Inc, OU=Testing, CN=foobar.tld, emailAddress=baz@foobar.tld', $certParser->getSubject());
    }

    public function testIssuerIsExtractedAndFormatted()
    {
        $certParser = CertParser::fromPemFile(self::getFilePath('2.pem'));
        $this->assertSame('C=DE, ST=Berlin, L=Berlin, O=FooBar Inc, OU=Testing CA, CN=foobar.tld, emailAddress=baz@foobar.tld', $certParser->getIssuer());
    }

    public function testMultipleComponentsInDistinguishedName()
    {
        if (PHP_VERSION <= '5.4.0') {
            $this->markTestSkipped('Works only with PHP >= 5.4');
        } else {
            $certParser = CertParser::fromPemFile(self::getFilePath('2-multi.pem'));
            $this->assertSame('C=DE, ST=Berlin, L=Berlin, O=FooBar Inc, OU=Testing Multi, OU=Foo, CN=multi.foobar.tld, emailAddress=baz@foobar.tld', $certParser->getSubject());
        }
    }
}
