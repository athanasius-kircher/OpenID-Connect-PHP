<?php
/**
 * Created by PhpStorm.
 * User: boellmann
 * Date: 06.03.19
 * Time: 22:43
 */

namespace AthanasiusTests\Configuration;

use Athanasius\Configuration\ProviderAutoDiscover;
use Athanasius\HttpClient\ClientInterface;
use Athanasius\Verification\JWK;
use PHPUnit\Framework\TestCase;
use Zend\Diactoros\Response;

class ProviderAutoDiscoverTest extends TestCase
{
    const TEST_CONFIGURATION_FILE = __DIR__ . '/openid-configuration.json';

    public function testOverrideGetProviderConfigValue()
    {
        $providerConfiguration = new ProviderAutoDiscover(
            $this->getMockBuilder(ClientInterface::class)->getMock(),
            ProviderArrayTest::TEST_VALID_PROVIDER_URL,
            ProviderArrayTest::TEST_CLIENT_ID,
            ProviderArrayTest::TEST_CLIENT_SECRETE,
            [
                'dummy'=>'dummy'
            ]
        );
        $this->assertSame('dummy', $providerConfiguration->getProviderConfigValue('dummy'));
    }

    public function testOverrideGetJWK()
    {
        $providerConfiguration = new ProviderAutoDiscover(
            $this->getMockBuilder(ClientInterface::class)->getMock(),
            ProviderArrayTest::TEST_VALID_PROVIDER_URL,
            ProviderArrayTest::TEST_CLIENT_ID,
            ProviderArrayTest::TEST_CLIENT_SECRETE,
            [
                'jwks'=>ProviderArrayTest::TEST_JWK
            ]
        );
        $jwk = $providerConfiguration->getJWK();
        $this->assertInstanceOf(JWK::class, $jwk);
        $this->assertIsArray($jwk->getKeys());
        $this->assertSame('RSA', ($jwk->getKeys())[0]->kty);
    }

    public function testGetProviderConfigValue()
    {
        $httpClientStub = $this->getMockBuilder(ClientInterface::class)
            ->getMock();
        $mockResponse = $this->getMockBuilder(Response::class)
            ->getMock();
        $httpClientStub
            ->expects($this->once())
            ->method('sendGet')
            ->with($this->equalTo(ProviderArrayTest::TEST_VALID_PROVIDER_URL .'/.well-known/openid-configuration'))
            ->willReturn($mockResponse);
        $mockResponse
            ->expects($this->once())
            ->method('getBody')
            ->willReturn(file_get_contents(self::TEST_CONFIGURATION_FILE));
        $providerConfiguration = new ProviderAutoDiscover(
            $httpClientStub,
            ProviderArrayTest::TEST_VALID_PROVIDER_URL,
            ProviderArrayTest::TEST_CLIENT_ID,
            ProviderArrayTest::TEST_CLIENT_SECRETE,
            []
        );
        $this->assertSame('https://openid.local/token', $providerConfiguration->getProviderConfigValue('token_endpoint'));
        $this->assertSame('fallback', $providerConfiguration->getProviderConfigValue('unset_value', 'fallback'));
    }

    public function testGetJWK()
    {
        $httpClientStub = $this->getMockBuilder(ClientInterface::class)
            ->getMock();
        $mockResponse = $this->getMockBuilder(Response::class)
            ->getMock();
        $httpClientStub
            ->expects($this->once())
            ->method('sendGet')
            ->with($this->equalTo('https://demo.openid.local/c2id/jwks.json'))
            ->willReturn($mockResponse);
        $mockResponse
            ->expects($this->once())
            ->method('getBody')
            ->willReturn(ProviderArrayTest::TEST_JWK);
        $providerConfiguration = new ProviderAutoDiscover(
            $httpClientStub,
            ProviderArrayTest::TEST_VALID_PROVIDER_URL,
            ProviderArrayTest::TEST_CLIENT_ID,
            ProviderArrayTest::TEST_CLIENT_SECRETE,
            [
                'jwks_uri'=>'https://demo.openid.local/c2id/jwks.json'
            ]
        );
        $jwk = $providerConfiguration->getJWK();
        $this->assertInstanceOf(JWK::class, $jwk);
        $this->assertIsArray($jwk->getKeys());
        $this->assertSame('RSA', ($jwk->getKeys())[0]->kty);


    }
}
