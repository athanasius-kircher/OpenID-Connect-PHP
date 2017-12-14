<?php
/**
 * Created by PhpStorm.
 * User: boellmann
 * Date: 11.12.17
 * Time: 07:41
 */

namespace Athanasius\Configuration;

use Athanasius\Exception\ConfigurationException;

interface ProviderInterface
{
    /**
     * @return string
     */
    public function getProviderUrl();
    /**
     * @return string
     */
    public function getClientId();
    /**
     * @return string
     */
    public function getClientSecret();
    /**
     * @param string $param
     * @param mixed $default
     * @return mixed
     * @throws ConfigurationException
     */
    public function getProviderConfigValue($param, $default = null);
}