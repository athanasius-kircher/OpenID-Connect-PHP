<?php
/**
 * Created by PhpStorm.
 * User: boellmann
 * Date: 14.12.17
 * Time: 21:41
 */

namespace Athanasius\Token;


use Athanasius\Utilities;

abstract class Token
{
    private $tokenString;

    /**
     * Token constructor.
     * @param $tokenString
     */
    public function __construct($tokenString)
    {
        $this->tokenString = $tokenString;
    }

    /**
     * @return mixed
     */
    public function getTokenString()
    {
        return $this->tokenString;
    }

    /**
     * @return object
     */
    public function getHeader() {
        return $this->decodeJWT($this->tokenString, 0);
    }

    /**
     * @return object
     */
    public function getPayload() {
        return $this->decodeJWT($this->tokenString, 1);
    }

    /**
     * @param $jwt string encoded JWT
     * @param int $section the section we would like to decode
     * @return object
     */
    protected function decodeJWT($jwt, $section = 0) {

        $parts = explode(".", $jwt);
        return json_decode(Utilities::base64urlDecode($parts[$section]));
    }

}