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

    /**
     * A wrapper around base64_decode which decodes Base64URL-encoded data,
     * which is not the same alphabet as base64.
     */
    public static function base64urlDecode($base64url) {
        return base64_decode(self::b64url2b64($base64url));
    }

    /**
     * Per RFC4648, "base64 encoding with URL-safe and filename-safe
     * alphabet".  This just replaces characters 62 and 63.  None of the
     * reference implementations seem to restore the padding if necessary,
     * but we'll do it anyway.
     *
     */
    private static function b64url2b64($base64url) {
        // "Shouldn't" be necessary, but why not
        $padding = strlen($base64url) % 4;
        if ($padding > 0) {
            $base64url .= str_repeat("=", 4 - $padding);
        }
        return strtr($base64url, '-_', '+/');
    }
}