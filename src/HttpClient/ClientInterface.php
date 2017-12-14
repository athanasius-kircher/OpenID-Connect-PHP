<?php
/**
 * Created by PhpStorm.
 * User: boellmann
 * Date: 14.12.17
 * Time: 19:37
 */

namespace Athanasius\HttpClient;


use Athanasius\Exception\ConnectionException;
use Psr\Http\Message\ResponseInterface;

interface ClientInterface
{
    /**
     * @param string $url
     * @param array $postData
     * @param array $headers
     * @throws ConnectionException
     * @return ResponseInterface
     */
    public function sendPost($url,array $postData,array $headers = array());

    /**
     * @param string $url
     * @param string $jsonString
     * @param array $headers
     * @throws ConnectionException
     * @return ResponseInterface
     */
    public function sendJsonViaPost($url,$jsonString,array $headers = array());

    /**
     * @param string $url
     * @param array $headers
     * @throws ConnectionException
     * @return ResponseInterface
     */
    public function sendGet($url,array $headers = array());
}