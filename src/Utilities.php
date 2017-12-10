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

    public static function getCurrentUri(ServerRequestInterface $request){
        /**
         * Thank you
         * http://stackoverflow.com/questions/189113/how-do-i-get-current-page-full-url-in-php-on-a-windows-iis-server
         */

        /*
         * Compatibility with multiple host headers.
         * The problem with SSL over port 80 is resolved and non-SSL over port 443.
         * Support of 'ProxyReverse' configurations.
         */

        $server = $request -> getServerParams();
        if (isset($server["HTTP_UPGRADE_INSECURE_REQUESTS"]) && ($server['HTTP_UPGRADE_INSECURE_REQUESTS'] == 1)) {
            $protocol = 'https';
        } else {
            $protocol = @$server['HTTP_X_FORWARDED_PROTO']
                ?: @$server['REQUEST_SCHEME']
                    ?: ((isset($server["HTTPS"]) && $server["HTTPS"] == "on") ? "https" : "http");
        }

        $port = @intval($server['HTTP_X_FORWARDED_PORT'])
            ?: @intval($server["SERVER_PORT"])
                ?: (($protocol === 'https') ? 443 : 80);

        $host = @explode(":", $server['HTTP_HOST'])[0]
            ?: @$server['SERVER_NAME']
                ?: @$server['SERVER_ADDR'];

        $port = (443 == $port) || (80 == $port) ? '' : ':' . $port;

        return sprintf('%s://%s%s/%s', $protocol, $host, $port, @trim(reset(explode("?", $server['REQUEST_URI'])), '/'));
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