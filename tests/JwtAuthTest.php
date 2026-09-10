<?php

namespace fidelize\JwtAuthKeys\Tests;

use DomainException;
use InvalidArgumentException;
use fidelize\JwtAuthKeys\JwtAuth;
use Firebase\JWT\SignatureInvalidException;
use PHPUnit\Framework\TestCase;

class JwtAuthTest extends TestCase
{
    public function testEncodeThrowsExceptionIfThereIsNoSecretAndNoKeysDirectory()
    {
        $this->expectException(DomainException::class);
        $this->expectExceptionMessage('No JWT secret or private key found.');

        $auth = new JwtAuth();
        $auth->encode('payload');
    }

    public function testEncodeThrowsExceptionIfThereIsAKeysDirectoryButItDoesNotExist()
    {
        $this->expectException(DomainException::class);
        $this->expectExceptionMessage('Directory not found: /invalid');

        $auth = new JwtAuth();
        $auth->setKeysDirectory('/invalid');
        $auth->encode('payload');
    }

    public function testEncodeThrowsExceptionIfThereIsAKeysDirectoryButNoPrivateKey()
    {
        $this->expectException(DomainException::class);
        $this->expectExceptionMessage('No JWT secret or private key found.');

        $auth = new JwtAuth();
        $auth->setKeysDirectory(
            __DIR__ . DIRECTORY_SEPARATOR . 'keys' . DIRECTORY_SEPARATOR . 'empty',
        );
        $auth->encode('payload');
    }

    public function testEncodeThrowsExceptionIfThereIsAKeysDirectoryButThereAreMultiplePrivateKeys()
    {
        $this->expectException(DomainException::class);
        $this->expectExceptionMessage('Multiple private keys found.');

        $auth = new JwtAuth();
        $auth->setKeysDirectory(
            __DIR__ . DIRECTORY_SEPARATOR . 'keys' . DIRECTORY_SEPARATOR . 'multiple-private',
        );
        $auth->encode('payload');
    }

    public function testEncodeReturnsJwtTokenUsingASinglePrivateKey()
    {
        $auth = new JwtAuth();
        $auth->setKeysDirectory(
            __DIR__ . DIRECTORY_SEPARATOR . 'keys' . DIRECTORY_SEPARATOR . 'single-private',
        );
        $result = $auth->encode('payload');
        $this->assertIsString($result);
        $this->assertNotEmpty($result);
    }

    public function testEncodeReturnsJwtTokenUsingASecret()
    {
        $auth = new JwtAuth();
        $auth->setSecret('a-secure-secret-key-for-testing-purposes-2024!');
        $result = $auth->encode('payload');
        $this->assertIsString($result);
        $this->assertEquals('payload', $auth->decode($result));
    }

    public function testDecodeThrowsExceptionIfThereIsAKeysDirectoryButItDoesNotExist()
    {
        $this->expectException(DomainException::class);
        $this->expectExceptionMessage('Directory not found: /invalid');

        $auth = new JwtAuth();
        $auth->setKeysDirectory('/invalid');
        $auth->decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.InBheWxvYWQi.YslbSUa5dxG0MhKBuLTqjZsjQSuQunNzKlvDSnyxrrE');
    }

    public function testDecodeReturnsOriginalPayloadUsingASecret()
    {
        $auth = new JwtAuth();
        $auth->setSecret('a-secure-secret-key-for-testing-purposes-2024!');
        $token = $auth->encode('payload');
        $result = $auth->decode($token);
        $this->assertEquals('payload', $result);
    }

    public function testDecodeReturnsOriginalPayloadUsingMultiplePublicKeys()
    {
        $auth = new JwtAuth();
        $auth->setKeysDirectory(
            __DIR__ . DIRECTORY_SEPARATOR . 'keys' . DIRECTORY_SEPARATOR . 'multiple-public',
        );
        $authSingle = new JwtAuth();
        $authSingle->setKeysDirectory(
            __DIR__ . DIRECTORY_SEPARATOR . 'keys' . DIRECTORY_SEPARATOR . 'single-private',
        );
        $jwt = $authSingle->encode('payload');
        $result = $auth->decode($jwt);
        $this->assertEquals('payload', $result);
    }
}
