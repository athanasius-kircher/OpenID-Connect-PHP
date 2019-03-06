<?php
/**
 * Created by PhpStorm.
 * User: boellmann
 * Date: 06.03.19
 * Time: 22:01
 */

namespace AthanasiusTests\Configuration;

use Athanasius\Configuration\ProviderArray;
use PHPUnit\Framework\TestCase;

class ProviderArrayTest extends TestCase
{
    const TEST_VALID_PROVIDER_URL = 'https://openid.local';

    const TEST_INVALID_PROVIDER_URL = 'openid.local';

    const TEST_CLIENT_ID = 'my_client_id';

    public function testGetClientId()
    {
        $providerConfiguration = new ProviderArray(
            self::TEST_VALID_PROVIDER_URL,
            self::TEST_CLIENT_ID
        );
        $this->assertSame(self::TEST_CLIENT_ID, $providerConfiguration->getClientId());
    }

    public function testGetProviderUrl()
    {
        $providerConfiguration = new ProviderArray(
            self::TEST_VALID_PROVIDER_URL
        );
        $this->assertSame(self::TEST_VALID_PROVIDER_URL, $providerConfiguration->getProviderUrl());
    }

    /**
     * @expectedException Athanasius\Exception\ConfigurationException
     */
    public function testInvalidProviderUrl()
    {
        $providerConfiguration = new ProviderArray(
            self::TEST_INVALID_PROVIDER_URL
        );
    }

    public function testGetProviderConfigValue()
    {

    }

    public function testGetJWK()
    {

    }

    public function testGetClientSecret()
    {

    }
}
