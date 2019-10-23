<?php

namespace fidelize\JwtAuthKeys;

use DomainException;
use Firebase\JWT\JWT;

class JwtAuth
{
    protected $secret;
    protected $keysDirectory;

    public function encode($payload)
    {
        $algorithm = 'HS256';
        $secret = $this->secret;

        if ($this->hasKeysDirectory()) {
            $privateKey = $this->getPrivateKey();

            if ($privateKey !== null) {
                $algorithm = 'RS256';
                $secret = $privateKey;
            }
        }

        if (empty($secret)) {
            throw new DomainException('No JWT secret or private key found.');
        }

        return JWT::encode($payload, $secret, $algorithm);
    }

    public function decode($msg)
    {
        if ($this->hasKeysDirectory()) {
            foreach ($this->getPublicKeys() as $publicKey) {
                try {
                    return JWT::decode($msg, $publicKey, ['RS256']);
                } catch (\Firebase\JWT\SignatureInvalidException $e) {
                } catch (\InvalidArgumentException $e) {
                } catch (DomainException $e) {
                    // If it is an invalid key, it should just try the next one
                    // If it is another kind of DomainException, it should fail
                    if (false === strpos($e->getMessage(), 'OpenSSL unable to verify data')) {
                        throw $e;
                    }
                }
            }
            // Fallback to using secret
        }
        return JWT::decode($msg, $this->secret, ['HS256']);
    }

    /**
     * PRIVATE key is used to generate new tokens. In order to be trusted,
     * the system receiving the token must validate it against the PUBLIC key.
     */
    private function getPrivateKey()
    {
        $files = $this->globKeys('*.key');

        if (count($files) > 1) {
            throw new DomainException('Multiple private keys found.');
        }

        if (count($files) == 0) {
            return;
        }

        return file_get_contents(array_pop($files));
    }

    /**
     * PUBLIC keys against which it will try to validate and trust the token.
     * Note that though you can trust and use the token, you are not able
     * to generate tokens using PUBLIC keys, only PRIVATE ones.
     */
    private function getPublicKeys()
    {
        $files = $this->globKeys('*.key.pub');
        $keys = [];

        foreach ($files as $file) {
            $keys[] = file_get_contents($file);
        }

        return $keys;
    }

    private function globKeys($pattern)
    {
        return glob($this->getKeysDirectory() . $pattern);
    }

    private function hasKeysDirectory()
    {
        if ($this->keysDirectory) {
            if (!file_exists($this->keysDirectory)) {
                throw new DomainException('Directory not found: ' . $this->keysDirectory);
            }

            return true;
        }
        return false;
    }

    private function getKeysDirectory()
    {
        return $this->keysDirectory . DIRECTORY_SEPARATOR;
    }

    public function setKeysDirectory($keysDirectory)
    {
        $this->keysDirectory = $keysDirectory;
        return $this;
    }

    public function setSecret($secret)
    {
        $this->secret = $secret;
        return $this;
    }
}
