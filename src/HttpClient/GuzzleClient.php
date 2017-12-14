<?php
/**
 * Created by PhpStorm.
 * User: boellmann
 * Date: 14.12.17
 * Time: 19:44
 */

namespace Athanasius\HttpClient;


use Athanasius\Exception\ConnectionException;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use Psr\Http\Message\ResponseInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;

final class GuzzleClient extends Client implements ClientInterface
{
    /**
     * @var string http proxy if necessary
     */
    private $httpProxy;

    /**
     * @var string full system path to the SSL certificate
     */
    private $certPath;

    /**
     * @var bool|string Compare guzzle request:verify
     */
    private $verify = true;
    /**
     * @var int timeout (seconds)
     */
    private $timeOut = 60;
    /**
     * @var LoggerInterface
     */
    private $logger;

    /**
     * @param string $httpProxy
     */
    public function setHttpProxy($httpProxy)
    {
        $this->httpProxy = $httpProxy;
    }

    /**
     * @param string $certPath
     */
    public function setCertPath($certPath)
    {
        $this->certPath = $certPath;
    }

    /**
     * @param bool|string $verify
     */
    public function setVerify($verify)
    {
        $this->verify = $verify;
    }

    /**
     * @param int $timeOut
     */
    public function setTimeOut($timeOut)
    {
        $this->timeOut = $timeOut;
    }

    /**
     * @param LoggerInterface $logger
     */
    public function setLogger($logger)
    {
        $this->logger = $logger;
    }

    /**
     * @param string $url
     * @param array $postData
     * @param array $headers
     * @return \Psr\Http\Message\ResponseInterface
     */
    public function sendPost($url, array $postData, array $headers = array())
    {

        $postString = http_build_query($postData, null, '&');
        $headers[] = "Content-Type: application/x-www-form-urlencoded";
        $headers[] = 'Content-Length: ' . strlen($postString);
        return $this -> doSend('POST',$url,$postString, $headers);
    }

    /**
     * @param string $url
     * @param string $jsonString
     * @param array $headers
     * @return \Psr\Http\Message\ResponseInterface
     */
    public function sendJsonViaPost($url, $jsonString, array $headers = array())
    {
        $headers[] = "Content-Type: application/json";
        $headers[] = 'Content-Length: ' . strlen($jsonString);
        return $this -> doSend('POST',$url,$jsonString, $headers);
    }

    /**
     * @param string $url
     * @param array $headers
     * @throws ConnectionException
     * @return ResponseInterface
     */
    public function sendGet($url,array $headers = array())
    {
        return $this -> doSend('GET',$url, $headers);
    }


    /**
     * @param $method
     * @param $url
     * @param null $bodyString
     * @param array $headers
     * @return \Psr\Http\Message\ResponseInterface
     * @throws ConnectionException
     */
    private function doSend($method, $url, $bodyString = null,$headers = array()) {


        try{
            $options = [];

            if (isset($this->httpProxy)) {
                $options['proxy'] = $this -> httpProxy;
            }

            // Allows to follow redirect
            $options['allow_redirects'] = [
                'max'             => 5,
                'strict'          => true,
                'referer'         => false,
                'protocols'       => ['http', 'https'],
                'track_redirects' => false
            ];

            /**
             * Set cert
             * Otherwise ignore SSL peer verification
             */
            if (isset($this->certPath)) {
                $options['cert'] = $this->certPath;
            }
            $options['verify'] = $this->verify;

            // Timeout in seconds
            $options['timeout'] = $this->timeOut;


            $request = new \GuzzleHttp\Psr7\Request($method, $url,$headers,$bodyString);
            // Download the given URL, and return output
            $response = $this -> send($request,$options);
            $this -> log(LogLevel::INFO, 'Connection success details',['response'=>$response,'request'=>$request]);
            return $response;

        }catch(GuzzleException $e){
            $this -> log(LogLevel::DEBUG, 'Connection failed details',['exception'=>$e,'request'=>$request]);
            throw new ConnectionException('Connection failed',0,$e);
        }
    }

    private function log($level,$message,array $context = array()){
        if($this -> logger){
            $this -> logger -> log($level,$message,$context);
        }
    }

}