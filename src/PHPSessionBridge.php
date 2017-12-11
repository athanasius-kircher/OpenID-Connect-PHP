<?php
/**
 * Created by PhpStorm.
 * User: boellmann
 * Date: 07.12.17
 * Time: 22:57
 */

namespace Athanasius;

/**
 * Class PHPSessionBridge simple session implementation
 * @package Athanasius
 */
class PHPSessionBridge implements SessionInterface
{
    public function get($key, $default = null)
    {
        if(isset($_SESSION[$key])){
            return $_SESSION[$key];
        }
        return $default;
    }

    public function set($key, $value)
    {
        $_SESSION[$key] = $value;
        return $this;
    }

    public function unsetByKey($key)
    {
        if(isset($_SESSION[$key])){
            unset($_SESSION[$key]);
        }
        return $this;
    }

}