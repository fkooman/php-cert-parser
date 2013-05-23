<?php

require_once 'src/fkooman/X509/CertParser.php';
require_once 'src/fkooman/X509/CertParserException.php';

use \fkooman\X509\CertParser as CertParser;
use \fkooman\X509\CertParserException as CertParserException;

class ClientRegistrationTest extends PHPUnit_Framework_TestCase
{

    public function testCert()
    {
        $dataDir = dirname(dirname(__DIR__)) . DIRECTORY_SEPARATOR . "data" . DIRECTORY_SEPARATOR;
        $testFiles = array ($dataDir . "1.pem", $dataDir . "1_flat.pem");

        foreach ($testFiles as $t) {
            $c = CertParser::fromFile($t);
            $this->assertEquals(1295864337, $c->getNotValidBefore());
            $this->assertEquals(1611397137, $c->getNotValidAfter());
            $this->assertEquals('/C=NL/ST=Utrecht/L=Utrecht/O=SURFnet B.V./OU=SURFconext/CN=engine.surfconext.nl', $c->getName());
            $this->assertEquals('a36aac83b9a552b3dc724bfc0d7bba6283af5f8e', $c->getFingerprint());
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

}
