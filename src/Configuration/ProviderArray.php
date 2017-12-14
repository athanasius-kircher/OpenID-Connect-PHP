<?php
/**
 * Created by PhpStorm.
 * User: boellmann
 * Date: 11.12.17
 * Time: 07:48
 */

namespace Athanasius\Configuration;


use Athanasius\Exception\ConfigurationException;

class ProviderArray implements ProviderInterface
{
    /**
     * @var string
     */
    private $providerUrl;
    /**
     * @var string
     */
    private $clientId;
    /**
     * @var string
     */
    private $clientSecret;
    /**
     * @var array
     */
    private $configuration;

    /**
     * ProviderArray constructor.
     * @param string $providerUrl
     * @param string $clientId
     * @param string $clientSecret
     * @param array $configuration
     */
    public function __construct($providerUrl, $clientId = '', $clientSecret = '', array $configuration = [])
    {
        $this->providerUrl = $providerUrl;
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->configuration = $configuration;
    }

    /**
     * @return string
     */
    public function getProviderUrl()
    {
        return $this -> providerUrl;
    }

    /**
     * @return string
     */
    public function getClientId()
    {
        return $this->clientId;
    }

    /**
     * @return string
     */
    public function getClientSecret()
    {
        return $this->clientSecret;
    }

    /**
     * @param string $param
     * @param null $default
     * @return mixed
     * @throws ConfigurationException
     */
    public function getProviderConfigValue($param, $default = null)
    {
        if (!isset($this -> configuration[$param])) {
            if(isset($default)) {
                // Uses default value if provided
                $this -> configuration[$param] = $default;
            } else {
                throw new ConfigurationException("The provider {$param} has not been set.");
            }
        }
        return $this->configuration[$param];
    }


}