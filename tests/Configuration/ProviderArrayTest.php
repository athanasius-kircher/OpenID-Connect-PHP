<?php
/**
 * Created by PhpStorm.
 * User: boellmann
 * Date: 06.03.19
 * Time: 22:01
 */

namespace AthanasiusTests\Configuration;

use Athanasius\Configuration\ProviderArray;
use Athanasius\Verification\JWK;
use PHPUnit\Framework\TestCase;

class ProviderArrayTest extends TestCase
{
    const TEST_VALID_PROVIDER_URL = 'https://openid.local';

    const TEST_INVALID_PROVIDER_URL = 'openid.local';

    const TEST_CLIENT_ID = 'my_client_id';

    const TEST_CLIENT_SECRETE = '62f66c6c6d616e6e';

    const TEST_JWK = '{"keys": [{"kty": "RSA","d": "FBj7uZoOjwouy_fCaxYuuJ1f5hrVWe6Z2LpobkL-pGPaUvZm0fyFuLgun57yWNuw2gbIIAbI6RGe1KMXGCXCpet9e3WrrCKekqPJ_jHj9I34BqyKjJH5bRZxj-A1OdI2d-w8YPSz5Z0EmC8RDRKFRY_-7eV-YRo_gQ18KVaJ_h6AhyeuqXPfHl5G5PHk-8JzUfyokpV959sPE1ZYttOd3QgL6Y8AUixP2DkKp8b1LoW-0MAh6Lv_FS79Flbj3IJ4C9rYOeZMVqawV495XAldNkGYK9tAf1HLCon3D27PCdQyRcgmi8AkcK1KoEj5FqCCKKJiV2AO1dpbefKd6wVrgQ","e": "AQAB","use": "sig","kid": "my_test_key","alg": "RS256","n": "h-Y3OEFMarrzYNjCepMeSn0bquo4i5Ffz4LvpCvezu_NCxzkAwvuY3iIthVk5QGhRgn9ApzQxMt8u0UXOUmA4729Mucl-j_i-nZ0e7fKE0emGvTwSXGGeROCplisRRU-f32GbG4CLJw3E9qhjII6UsK7zCKOYnx6AxcQjn49MO_Lymt0Z0BdKVq07CRjPo538q_7BKQG1sUZTFO8e-t0FLFrShBfAs3tQ-GnvmxDuvSb1pHjUwfpW7i-oaOM8nO-NFFD7S84HA5AAfNWl5yPc_FnXhSxrwG6IUuALxUycM6cEKO_dYl4Epyy-IeLrPhE-1-bwVK5ceNmxsYVqCrshQ"}]}';

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
        $providerConfiguration = new ProviderArray(
            self::TEST_VALID_PROVIDER_URL,
            self::TEST_CLIENT_ID,
            self::TEST_CLIENT_SECRETE,
            [
                'dummy'=>'dummy'
            ]
        );
        $this->assertSame('dummy', $providerConfiguration->getProviderConfigValue('dummy'));
        $this->assertSame('fallback', $providerConfiguration->getProviderConfigValue('unsetdummy','fallback'));
    }

    public function testGetJWK()
    {
        $providerConfiguration = new ProviderArray(
            self::TEST_VALID_PROVIDER_URL,
            self::TEST_CLIENT_ID,
            self::TEST_CLIENT_SECRETE,
            [
                'jwks'=>self::TEST_JWK
            ]
        );
        $jwk = $providerConfiguration->getJWK();
        $this->assertInstanceOf(JWK::class, $jwk);
        $this->assertIsArray($jwk->getKeys());
        $this->assertSame('RSA', ($jwk->getKeys())[0]->kty);
    }

    public function testGetClientSecret()
    {
        $providerConfiguration = new ProviderArray(
            self::TEST_VALID_PROVIDER_URL,
            self::TEST_CLIENT_ID,
            self::TEST_CLIENT_SECRETE
        );
        $this->assertSame(self::TEST_CLIENT_SECRETE, $providerConfiguration->getClientSecret());
    }
}
