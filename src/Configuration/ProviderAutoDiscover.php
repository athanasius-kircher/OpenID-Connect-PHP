<?php
/**
 * Created by PhpStorm.
 * User: boellmann
 * Date: 14.12.17
 * Time: 06:44
 */

namespace Athanasius\Configuration;


use GuzzleHttp\ClientInterface;

class ProviderAutoDiscover extends ProviderArray
{
    /**
     * @var ClientInterface
     */
    private $httpClient;

    public function __construct(ClientInterface $httpClient, $providerUrl, $clientId = '', $clientSecret = '', array $configuration = [])
    {
        $this -> httpClient = $httpClient;
        parent::__construct($providerUrl, $clientId, $clientSecret, $configuration);
    }


    /**
     * Get's anything that we need configuration wise including endpoints, and other values
     *
     * @param $param
     * @param string $default optional
     * @throws OpenIDConnectClientException
     * @return string
     *
     */
    private function getProviderConfigValue($param, $default = null) {

        // If the configuration value is not available, attempt to fetch it from a well known config endpoint
        // This is also known as auto "discovery"
        if (!isset($this->providerConfig[$param])) {
            if(!$this->wellKnown){
                $well_known_config_url = rtrim($this -> getProviderUrl(),"/") . "/.well-known/openid-configuration";
                $this->wellKnown = json_decode($this->fetchURL($well_known_config_url));
            }

            $value = false;
            if(isset($this->wellKnown->{$param})){
                $value = $this->wellKnown->{$param};
            }

            if ($value) {
                $this->providerConfig[$param] = $value;
            } elseif(isset($default)) {
                // Uses default value if provided
                $this->providerConfig[$param] = $default;
            } else {
                throw new OpenIDConnectClientException("The provider {$param} has not been set. Make sure your provider has a well known configuration available.");
            }

        }

        return $this->providerConfig[$param];
    }
}