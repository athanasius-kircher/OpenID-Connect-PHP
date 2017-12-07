<?php
/**
 * Created by PhpStorm.
 * User: boellmann
 * Date: 06.12.17
 * Time: 08:16
 */

namespace Jumbojett;


use Psr\Http\Message\ServerRequestInterface;

class Utilities
{
    public static function getParameterFromRequest(ServerRequestInterface $request,$key,$default = null){
        $get = $request -> getQueryParams();
        if(isset($get[$key])){
            return $get[$key];
        }
        $post = $request -> getParsedBody();
        if(isset($post[$key])){
            return $post[$key];
        }
        return $default;
    }
}