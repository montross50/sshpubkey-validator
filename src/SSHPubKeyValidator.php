<?php

namespace montross50\SSHPubKeyValidator;

use phpseclib\Crypt\RSA;

class SSHPubKeyValidator
{
    /**
     * @var $crypto RSA
     */
    private $crypto;
    private $strict;
    const RSA_MIN_LENGTH_STRICT = 1024;
    const RSA_MAX_LENGTH_STRICT = 16384;
    const RSA_MIN_LENGTH_LOOSE = 768;
    const RSA_MAX_LENGTH_LOOSE = 16384;

    public function __construct($crypto = null, $strict = true)
    {
        if ($crypto === null) {
            $crypto = new RSA();
        }
        $this->crypto = $crypto;
        $this->strict = $strict;
    }

    public function validateKey($pubkey)
    {
        //first we check basic validity
        $key_parts = explode(' ', $pubkey, 3);
        if (count($key_parts) < 2) {
            return false;
        }
        $algorithm = $key_parts[0];
        $key = $key_parts[1];
        if (!in_array($algorithm, array('ssh-rsa'))) {
            return false;
        }
        $key_base64_decoded = base64_decode($key, true);
        if ($key_base64_decoded === false) {
            return false;
        }
        $check = base64_decode(substr($key, 0, 16));
        $check = preg_replace("/[^\w\-]/", "", $check);
        if ((string) $check !== (string) $algorithm) {
            return false;
        }
        //now we check if the key is truly valid
        $this->crypto->loadKey($pubkey, RSA::PUBLIC_FORMAT_OPENSSH);
        $pkcs8key = $this->crypto->getPublicKey(RSA::PUBLIC_FORMAT_PKCS8);

        $opensslPubKey = openssl_pkey_get_public($pkcs8key);
        if ($opensslPubKey === false) {
            return false;
        }
        $keyData = openssl_pkey_get_details($opensslPubKey);
        if($keyData === false){
            return false;
        }
        if ($this->strict) {
            $minLength = self::RSA_MIN_LENGTH_STRICT;
            $maxLength = self::RSA_MAX_LENGTH_STRICT;
        } else {
            $minLength = self::RSA_MIN_LENGTH_LOOSE;
            $maxLength = self::RSA_MAX_LENGTH_LOOSE;
        }
        if (isset($keyData['bits'])) {
            if ($keyData['bits'] < $minLength) {
                return false;
            }
            if ($keyData['bits'] > $maxLength) {
                return false;
            }
        } else {
            return false;
        }
        //everything is valid it seems
        return true;
    }

    public function getFingerprint($pubkey, $algo = 'md5')
    {
        $this->crypto->loadKey($pubkey, RSA::PUBLIC_FORMAT_OPENSSH);
        return $this->crypto->getPublicKeyFingerprint($algo);
    }
}
