<?php

require_once 'lib/fkooman/x509/CertParser.php';
require_once 'lib/fkooman/x509/CertParserException.php';

use \fkooman\x509\CertParser as CertParser;
use \fkooman\x509\CertParserException as CertParserException;

class ClientRegistrationTest extends PHPUnit_Framework_TestCase
{

    public function testCert()
    {
        $dataDir = dirname(dirname(__DIR__)) . DIRECTORY_SEPARATOR . "data" . DIRECTORY_SEPARATOR;
        $testFiles = array ($dataDir . "1.pem", $dataDir . "1_flat.pem");

        foreach ($testFiles as $t) {
            $c = CertParser::fromFile($t);
            $this->assertEquals(1611397137, $c->getExpiry());
            $this->assertEquals('/C=NL/ST=Utrecht/L=Utrecht/O=SURFnet B.V./OU=SURFconext/CN=engine.surfconext.nl', $c->getName());
        }
    }

    /**
     * @expectedException \fkooman\x509\CertParserException
     * @expectedExceptionMessage unable to parse the certificate
     */
    public function testBrokenData()
    {
        $c = new CertParser("foo");
    }

}
