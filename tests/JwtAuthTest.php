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
            __DIR__ . DIRECTORY_SEPARATOR . 'keys' . DIRECTORY_SEPARATOR . 'empty'
        );
        $auth->encode('payload');
    }

    public function testEncodeThrowsExceptionIfThereIsAKeysDirectoryButThereAreMultiplePrivateKeys()
    {
        $this->expectException(DomainException::class);
        $this->expectExceptionMessage('Multiple private keys found.');

        $auth = new JwtAuth();
        $auth->setKeysDirectory(
            __DIR__ . DIRECTORY_SEPARATOR . 'keys' . DIRECTORY_SEPARATOR . 'multiple-private'
        );
        $auth->encode('payload');
    }

    public function testEncodeReturnsJwtTokenUsingASinglePrivateKey()
    {
        $auth = new JwtAuth();
        $auth->setKeysDirectory(
            __DIR__ . DIRECTORY_SEPARATOR . 'keys' . DIRECTORY_SEPARATOR . 'single-private'
        );
        $result = $auth->encode('payload');
        $jwt = <<<'EOT'
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.InBheWxvYWQi.jckjbHGYeLZLJVKV4PhhSQ4vtz84BR8yZ6vYsQ8KOpqqmI8UbhjH3Omrve-smRj9I-h_GiV_MiBnE1-zflLnPObnhl-Ze0ZmaXOaI3QLOsUtlgqWQ1F6Og9d-nY4eJ1aPMgezb7EOmdMTEzPaiLGFZHiIeIdLQEp0mSUJUO8q3Tjw79BcThNVe-P1hr8moNgNdkqffWznt5WvGwfyIm17AAkUFERxzbErgrLFcDj-j07yThxXzs776gcSGN2RyO3Sph2DuwbbTMK76xo1dutdXz-qL48mliSRnTlSZimmYhpHOUAsyHoz69GVS8P8euO2GAuXyON1QjDOjxLwSBMmhR1hE_O5PRvNOSNGAFO5nml3trMth-RYLIt6eJuq9c0BVirs2H6cIi37JzhLR-e7-zpNccSQdX7Y8k6f9N8lfFbPeHozktCukygJH146zWBN-BUFmF0KfkmDAeRe7i4W85qNPgTB6-pSTgkNen4o0oot8eE4UQxrJZ464yKevVkwb_6_EK2FS2R9zYPuGL3LMz6l-7zYvmd23J7ynG0NP1c9sMRBYAhkRacimevmZ4CNv_MKwSTa4YRClenchnn0upetgvgkDih-1sdcyU1Bvd5ASsEE1D09QUqAME4GqptDy8vRYG7ZeF11hQbp0BKrqjCsc2nRaHwdjaJZHlOXG4
EOT;
        $this->assertEquals($jwt, $result);
    }

    public function testEncodeReturnsJwtTokenUsingASecret()
    {
        $auth = new JwtAuth();
        $auth->setSecret('shht');
        $result = $auth->encode('payload');
        $jwt = <<<'EOT'
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.InBheWxvYWQi.YslbSUa5dxG0MhKBuLTqjZsjQSuQunNzKlvDSnyxrrE
EOT;
        $this->assertEquals($jwt, $result);
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
        $auth->setSecret('shht');
        $result = $auth->decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.InBheWxvYWQi.YslbSUa5dxG0MhKBuLTqjZsjQSuQunNzKlvDSnyxrrE');
        $this->assertEquals('payload', $result);
    }

    public function testDecodeReturnsOriginalPayloadUsingMultiplePublicKeys()
    {
        $auth = new JwtAuth();
        $auth->setKeysDirectory(
            __DIR__ . DIRECTORY_SEPARATOR . 'keys' . DIRECTORY_SEPARATOR . 'multiple-public'
        );
        $jwt = <<<'EOT'
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.InBheWxvYWQi.jckjbHGYeLZLJVKV4PhhSQ4vtz84BR8yZ6vYsQ8KOpqqmI8UbhjH3Omrve-smRj9I-h_GiV_MiBnE1-zflLnPObnhl-Ze0ZmaXOaI3QLOsUtlgqWQ1F6Og9d-nY4eJ1aPMgezb7EOmdMTEzPaiLGFZHiIeIdLQEp0mSUJUO8q3Tjw79BcThNVe-P1hr8moNgNdkqffWznt5WvGwfyIm17AAkUFERxzbErgrLFcDj-j07yThxXzs776gcSGN2RyO3Sph2DuwbbTMK76xo1dutdXz-qL48mliSRnTlSZimmYhpHOUAsyHoz69GVS8P8euO2GAuXyON1QjDOjxLwSBMmhR1hE_O5PRvNOSNGAFO5nml3trMth-RYLIt6eJuq9c0BVirs2H6cIi37JzhLR-e7-zpNccSQdX7Y8k6f9N8lfFbPeHozktCukygJH146zWBN-BUFmF0KfkmDAeRe7i4W85qNPgTB6-pSTgkNen4o0oot8eE4UQxrJZ464yKevVkwb_6_EK2FS2R9zYPuGL3LMz6l-7zYvmd23J7ynG0NP1c9sMRBYAhkRacimevmZ4CNv_MKwSTa4YRClenchnn0upetgvgkDih-1sdcyU1Bvd5ASsEE1D09QUqAME4GqptDy8vRYG7ZeF11hQbp0BKrqjCsc2nRaHwdjaJZHlOXG4
EOT;
        $result = $auth->decode($jwt);
        $this->assertEquals('payload', $result);
    }
}
