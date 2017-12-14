<?php
/**
 * Created by PhpStorm.
 * User: boellmann
 * Date: 14.12.17
 * Time: 21:41
 */

namespace Athanasius\Token;


use Athanasius\Utilities;

class IdToken extends Token
{
    public function getSignature(){
        $parts = explode(".", $this -> getTokenString());
        return Utilities::base64urlDecode(array_pop($parts));
    }

    public function getPayloadStringWithHeader(){
        $parts = explode(".", $this -> getTokenString());
        array_pop($parts);
        return implode('.',$parts);
    }
}