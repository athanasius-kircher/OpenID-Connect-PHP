<?php
/**
 * Created by PhpStorm.
 * User: boellmann
 * Date: 14.12.2017
 * Time: 22:43
 */

namespace Athanasius\Verification;


class JWK
{
    private $jsonString;

    /**
     * JWK constructor.
     * @param string $jsonString
     */
    public function __construct($jsonString)
    {
        $this->jsonString = $jsonString;
    }

    public function getKeys(){
        $jwk = json_decode($this -> jsonString);
        return $jwk->keys;
    }


}