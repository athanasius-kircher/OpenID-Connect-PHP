<?php
/**
 * Created by PhpStorm.
 * User: boellmann
 * Date: 11.12.17
 * Time: 07:41
 */

namespace Athanasius\Configuration;

interface ProviderInterface
{
    public function getProviderUrl();

    public function getClientId();

    public function getClientSecret();
}