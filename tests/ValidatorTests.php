<?php

namespace montross50\SSHPubKeyValidator;

use phpseclib\Crypt\RSA;

class ValidatorTests extends \PHPUnit\Framework\TestCase
{
    use \phpmock\phpunit\PHPMock;

    public function testValidateKeyFailsOnInvalidFormatTooSmall()
    {
        $lib = new SSHPubKeyValidator();
        $result = $lib->validateKey("AAAAB3NzaC1yc2EAAAADAQABAAAAgQCbIEIZZ1TOwy4eJyk5XK5chARjnGJnfvJUbDBrDuyYqPsAgX/uoHWV/T8XN80cwpTcLalfS");
        $this->assertFalse($result);
    }

    public function testValidateKeyFailsWithInvalidLeadingText()
    {
        $lib = new SSHPubKeyValidator();
        $result = $lib->validateKey("ssh-foo AAAAB3NzaC1yc2EAAAADAQABAAAAgQCbIEIZZ1TOwy4eJyk5XK5chARjnGJnfvJUbDBrDuyYqPsAgX/uoHWV/T8XN80cwpTcLalfS");
        $this->assertFalse($result);
    }

    public function testValidateKeyFailsOnBadKeyFormat()
    {
        $lib = new SSHPubKeyValidator();
        $result = $lib->validateKey("ssh-rsa fail!");
        $this->assertFalse($result);
    }

    public function testValidateKeyFailsOnBadAlgoCheck()
    {
        $lib = new SSHPubKeyValidator();
        $key = base64_encode("this should fail");
        $result = $lib->validateKey("ssh-rsa $key");
        $this->assertFalse($result);
    }

    public function testValidateKeyFailsOnUnabledToLoadKey()
    {
        $crypto = \Mockery::mock(RSA::class);
        $crypto->shouldReceive('loadKey');
        $crypto->shouldReceive('getPublicKey')->andReturn(false);
        $lib = new SSHPubKeyValidator($crypto);
        $result = $lib->validateKey("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDprgc7bT6PscqJrKKZ2d3COBOpmJ8osFIv/pWOzEw5cSLNArahiGG4afwzRWWlsENCbP1zs32EQH/kTBcatzGAUEKGFASXohlI/Hn1UgRzfXJISa2LGfDno6tyokPIwZbIGCsAAgWW206CLg4BG7FTnG+wgfdB177eurdR4Fg2E06gVwCFRdF4qpAPgPRiBQeZu67rUqsiDjBXF0p67SNshOm3z9nCSHT++kzpwLPEfs+i7+TkBSjZu959oMJrEp+EdPnY5N3Q781NLdn/q3GzYrnEaJ+KC3biM+ZM9iIh6eVeLOjReluckLkSiuLe3W3R58zGN3RmgnOkKgZ9pslB valid-key");
        $this->assertFalse($result);
    }

    public function testValidateKeyFailsOnFailureToParseWithOpenssl()
    {
        $ossl = $this->getFunctionMock(__NAMESPACE__, "openssl_pkey_get_details");
        $ossl2 = $this->getFunctionMock(__NAMESPACE__, "openssl_pkey_get_public");
        $ossl->expects($this->any())->willReturn(false);
        $ossl2->expects($this->any())->willReturn(true);
        $lib = new SSHPubKeyValidator();
        $result = $lib->validateKey("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDprgc7bT6PscqJrKKZ2d3COBOpmJ8osFIv/pWOzEw5cSLNArahiGG4afwzRWWlsENCbP1zs32EQH/kTBcatzGAUEKGFASXohlI/Hn1UgRzfXJISa2LGfDno6tyokPIwZbIGCsAAgWW206CLg4BG7FTnG+wgfdB177eurdR4Fg2E06gVwCFRdF4qpAPgPRiBQeZu67rUqsiDjBXF0p67SNshOm3z9nCSHT++kzpwLPEfs+i7+TkBSjZu959oMJrEp+EdPnY5N3Q781NLdn/q3GzYrnEaJ+KC3biM+ZM9iIh6eVeLOjReluckLkSiuLe3W3R58zGN3RmgnOkKgZ9pslB valid-key");
        $this->assertFalse($result);
    }

    public function testValidateKeyFailsOnInvalidParseWithOpenssl()
    {
        //this may not technically be possible
        $ossl = $this->getFunctionMock(__NAMESPACE__, "openssl_pkey_get_details");
        $ossl2 = $this->getFunctionMock(__NAMESPACE__, "openssl_pkey_get_public");
        $ossl->expects($this->any())->willReturn(['foo'=>1]);
        $ossl2->expects($this->any())->willReturn(true);
        $lib = new SSHPubKeyValidator();
        $result = $lib->validateKey("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDprgc7bT6PscqJrKKZ2d3COBOpmJ8osFIv/pWOzEw5cSLNArahiGG4afwzRWWlsENCbP1zs32EQH/kTBcatzGAUEKGFASXohlI/Hn1UgRzfXJISa2LGfDno6tyokPIwZbIGCsAAgWW206CLg4BG7FTnG+wgfdB177eurdR4Fg2E06gVwCFRdF4qpAPgPRiBQeZu67rUqsiDjBXF0p67SNshOm3z9nCSHT++kzpwLPEfs+i7+TkBSjZu959oMJrEp+EdPnY5N3Q781NLdn/q3GzYrnEaJ+KC3biM+ZM9iIh6eVeLOjReluckLkSiuLe3W3R58zGN3RmgnOkKgZ9pslB valid-key");
        $this->assertFalse($result);
    }

    public function testValidateKeyFailsOnTooFewBits()
    {
        $lib = new SSHPubKeyValidator();
        $result = $lib->validateKey("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAQQC+5L+Y56foVA+uioKtAsm4DPZMgDQoSjHedpU/h1lBV8bA7C3qsnK3WzA6k44TRDddZB2ZTtl94JccI01h5eDp phpseclib-generated-key");
        $this->assertFalse($result);
    }

    public function testValidateKeyFailsOnTooManyBits()
    {
        $lib = new SSHPubKeyValidator();
        $result = $lib->validateKey("ssh-rsa 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 phpseclib-generated-key");
        $this->assertFalse($result);
    }

    public function testValidateKeySuccess()
    {
        $lib = new SSHPubKeyValidator();
        $result = $lib->validateKey("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDprgc7bT6PscqJrKKZ2d3COBOpmJ8osFIv/pWOzEw5cSLNArahiGG4afwzRWWlsENCbP1zs32EQH/kTBcatzGAUEKGFASXohlI/Hn1UgRzfXJISa2LGfDno6tyokPIwZbIGCsAAgWW206CLg4BG7FTnG+wgfdB177eurdR4Fg2E06gVwCFRdF4qpAPgPRiBQeZu67rUqsiDjBXF0p67SNshOm3z9nCSHT++kzpwLPEfs+i7+TkBSjZu959oMJrEp+EdPnY5N3Q781NLdn/q3GzYrnEaJ+KC3biM+ZM9iIh6eVeLOjReluckLkSiuLe3W3R58zGN3RmgnOkKgZ9pslB valid-key");
        $this->assertTrue($result);
    }

    public function testValidateKeySuccessNonStrict()
    {
        $lib = new SSHPubKeyValidator(null, false);
        $result = $lib->validateKey("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAYQDPNTF5Nngt1ZjAWXeSn2Qa61pSLWk3X/rEx4Tf7OO85mVpP6HVVYQ/zlTfEmdxhQ2mtcH6URnpIzHlzXrcHG/HsuPq4/p0BUuB5yFUNxgwcmjOFmmqYsT7pwXk1RJERYc= phpseclib-generated-key");
        $this->assertTrue($result);
    }

    public function testGetFingerprint()
    {
        $key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDprgc7bT6PscqJrKKZ2d3COBOpmJ8osFIv/pWOzEw5cSLNArahiGG4afwzRWWlsENCbP1zs32EQH/kTBcatzGAUEKGFASXohlI/Hn1UgRzfXJISa2LGfDno6tyokPIwZbIGCsAAgWW206CLg4BG7FTnG+wgfdB177eurdR4Fg2E06gVwCFRdF4qpAPgPRiBQeZu67rUqsiDjBXF0p67SNshOm3z9nCSHT++kzpwLPEfs+i7+TkBSjZu959oMJrEp+EdPnY5N3Q781NLdn/q3GzYrnEaJ+KC3biM+ZM9iIh6eVeLOjReluckLkSiuLe3W3R58zGN3RmgnOkKgZ9pslB valid-key";
        $content = explode(' ', $key, 3);
        $fingerprint =  join(':', str_split(md5(base64_decode($content[1])), 2));
        $lib = new SSHPubKeyValidator();
        $result = $lib->getFingerprint($key);
        $this->assertEquals($fingerprint, $result);
    }
}
