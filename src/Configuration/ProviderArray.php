<?php
/**
 * Created by PhpStorm.
 * User: boellmann
 * Date: 11.12.17
 * Time: 07:48
 */

namespace Athanasius\Configuration;


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



}