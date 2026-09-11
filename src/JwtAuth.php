<?php

declare(strict_types=1);

namespace fidelize\JwtAuthKeys;

use DomainException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use SensitiveParameter;

class JwtAuth
{
    protected ?string $secret = null;
    protected ?string $keysDirectory = null;

    /**
     * @param array<string, mixed>|string $payload
     */
    public function encode(array|string $payload): string
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

        if ($secret === null || $secret === '') {
            throw new DomainException('No JWT secret or private key found.');
        }

        if (is_string($payload)) {
            $payload = ['__payload__' => $payload];
        }

        return JWT::encode($payload, $secret, $algorithm);
    }

    public function decode(string $msg): mixed
    {
        if ($this->hasKeysDirectory()) {
            foreach ($this->getPublicKeys() as $publicKey) {
                try {
                    return $this->normalizeDecodedPayload(JWT::decode($msg, new Key($publicKey, 'RS256')));
                } catch (\Firebase\JWT\SignatureInvalidException|\InvalidArgumentException) {
                } catch (DomainException $e) {
                    // If it is an invalid key, it should just try the next one
                    // If it is another kind of DomainException, it should fail
                    if (!str_contains($e->getMessage(), 'OpenSSL unable to verify data')) {
                        throw $e;
                    }
                }
            }
            // Fallback to using secret
        }

        if ($this->secret === null || $this->secret === '') {
            throw new DomainException('No JWT secret or private key found.');
        }

        return $this->normalizeDecodedPayload(JWT::decode($msg, new Key($this->secret, 'HS256')));
    }

    /**
     * PRIVATE key is used to generate new tokens. In order to be trusted,
     * the system receiving the token must validate it against the PUBLIC key.
     */
    private function getPrivateKey(): ?string
    {
        $files = $this->globKeys('*.key');

        if (count($files) > 1) {
            throw new DomainException('Multiple private keys found.');
        }

        if (count($files) === 0) {
            return null;
        }

        $contents = file_get_contents(array_pop($files));

        return $contents === false ? null : $contents;
    }

    /**
     * PUBLIC keys against which it will try to validate and trust the token.
     * Note that though you can trust and use the token, you are not able
     * to generate tokens using PUBLIC keys, only PRIVATE ones.
     *
     * @return list<string>
     */
    private function getPublicKeys(): array
    {
        $files = $this->globKeys('*.key.pub');
        $keys = [];

        foreach ($files as $file) {
            $contents = file_get_contents($file);
            if ($contents !== false) {
                $keys[] = $contents;
            }
        }

        return $keys;
    }

    /**
     * @return list<string>
     */
    private function globKeys(string $pattern): array
    {
        $files = glob($this->getKeysDirectory() . $pattern);

        return $files === false ? [] : $files;
    }

    private function hasKeysDirectory(): bool
    {
        if ($this->keysDirectory) {
            if (!file_exists($this->keysDirectory)) {
                throw new DomainException('Directory not found: ' . $this->keysDirectory);
            }

            return true;
        }

        return false;
    }

    private function getKeysDirectory(): string
    {
        if ($this->keysDirectory === null) {
            throw new DomainException('Keys directory is not set.');
        }

        return $this->keysDirectory . DIRECTORY_SEPARATOR;
    }

    public function setKeysDirectory(string $keysDirectory): self
    {
        $this->keysDirectory = $keysDirectory;

        return $this;
    }

    public function setSecret(#[SensitiveParameter] string $secret): self
    {
        $this->secret = $secret;

        return $this;
    }

    private function normalizeDecodedPayload(object $decoded): mixed
    {
        if (property_exists($decoded, '__payload__')) {
            $properties = get_object_vars($decoded);

            if (count($properties) === 1) {
                return $decoded->__payload__;
            }
        }

        return $decoded;
    }
}
