<?php
/**
 * Created by PhpStorm.
 * User: boellmann
 * Date: 07.12.17
 * Time: 22:37
 */

namespace Athanasius\Session;

/**
 * Interface SessionInterface
 * @package Athanasius
 */
interface SessionInterface
{
    /**
     * @param string $key
     * @param mixed $default
     * @return mixed
     */
    public function get($key,$default=null);

    /**
     * @param string $key
     * @param mixed $value
     * @return SessionInterface
     */
    public function set($key,$value);

    /**
     * @param $key
     * @return SessionInterface
     */
    public function unsetByKey($key);
}