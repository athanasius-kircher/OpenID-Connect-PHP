<?php
/**
 * Created by PhpStorm.
 * User: boellmann
 * Date: 14.12.17
 * Time: 06:44
 */

namespace Athanasius\Configuration;

use Athanasius\Exception\ConfigurationException;
use Athanasius\HttpClient\ClientInterface;

class ProviderAutoDiscover extends ProviderArray
{
    /**
     * @var ClientInterface
     */
    private $httpClient;
    /**
     * @var \stdClass
     */
    private $wellKnown;

    /**
     * ProviderAutoDiscover constructor.
     * @param ClientInterface $httpClient
     * @param string $providerUrl
     * @param string $clientId
     * @param string $clientSecret
     * @param array $configuration
     */
    public function __construct(ClientInterface $httpClient, $providerUrl, $clientId = '', $clientSecret = '', array $configuration = [])
    {
        $this -> httpClient = $httpClient;
        parent::__construct($providerUrl, $clientId, $clientSecret, $configuration);
    }

    /**
     * @param string $param
     * @param null $default
     * @return mixed|null
     * @throws ConfigurationException
     */
    public function getProviderConfigValue($param, $default = null) {
        try{
            $config = parent::getProviderConfigValue($param,$default);
            return $config;
        }catch(ConfigurationException $e){
            if(!$this->wellKnown){
                $wellKnownUrl  = rtrim($this -> getProviderUrl(),"/") . "/.well-known/openid-configuration";
                $response = $this -> httpClient -> sendGet($wellKnownUrl);
                $configurationObject = json_decode($response -> getBody());
                if(null === $configurationObject){
                    throw new ConfigurationException(sprintf('Configuration could not be loaded under: "%s"',$wellKnownUrl));
                }
                $this->wellKnown = $configurationObject;
            }
            if(isset($this->wellKnown->{$param})){
                return $this->wellKnown->{$param};
            }elseif(isset($default)) {
                return $default;
            } else {
                throw new ConfigurationException(sprintf('The provider "%s" has not been set. Make sure your provider has a well known configuration available.',$param));
            }
        }
    }
}