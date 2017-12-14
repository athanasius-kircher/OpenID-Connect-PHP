<?php

/**
 *
 * Copyright MITRE 2017
 *
 * OpenIDConnectClient for PHP5
 * Author: Michael Jett <mjett@mitre.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 */

namespace Athanasius;


use Athanasius\Configuration\ProviderArray;
use Athanasius\Configuration\ProviderInterface;
use Athanasius\Exception\InvalidReponseType;
use Athanasius\Exception\VerificationException;
use Athanasius\HttpClient\ClientInterface;
use Athanasius\Session\SessionInterface;
use Athanasius\Exception\OpenIDConnectClientException;
use Athanasius\Token\AccessToken;
use Athanasius\Token\IdToken;
use Athanasius\Token\RefreshToken;
use Athanasius\Verification\JWTVerification;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;

/**
 * Class OpenIDConnectClient
 * @package Athanasius
 * @todo implement clean OpenID Spec methods and no aggregation as in authenticate
 * @todo add Unit Tests
 * @todo overwork examples
 */
final class OpenIDConnectClient
{
    /**
     * @var AccessToken
     */
    private $accessToken;

    /**
     * @var RefreshToken
     */
    private $refreshToken;

    /**
     * @var IdToken
     */
    private $idToken;

    /**
     * @var array holds scopes
     */
    private $scopes = array();

    /**
     * @var array holds response types
     */
    private $responseTypes = array();

    /**
     * @var array holds a cache of info returned from the user info endpoint
     */
    private $userInfo = array();

    /**
     * @var SessionInterface
     */
    private $sessionStorage;
    /**
     * @var ClientInterface
     */
    private $httpClient;
    /**
     * @var ProviderInterface
     */
    private $configuration;
    /**
     * @var LoggerInterface
     */
    private $logger;

    /**
     * OpenIDConnectClient constructor.
     * @param ProviderInterface $configuration
     * @param SessionInterface $sessionStorage
     * @param ClientInterface $httpClient
     */
    public function __construct(ProviderInterface $configuration, SessionInterface $sessionStorage, ClientInterface $httpClient) {
        $this -> sessionStorage = $sessionStorage;
        $this -> configuration = $configuration;
        $this -> client = $httpClient;
    }

    /**
     * @param $response_types
     */
    public function setResponseTypes($response_types) {
        $this->responseTypes = array_merge($this->responseTypes, (array)$response_types);
    }

    /**
     * @param LoggerInterface $logger
     */
    public function setLogger($logger)
    {
        $this->logger = $logger;
    }

    /**
     * @param ServerRequestInterface $request
     * @param string $redirectUri
     * @return bool
     * @throws OpenIDConnectClientException
     */
    public function authenticate(ServerRequestInterface $request, $redirectUri) {

        // Do a preemptive check to see if the provider has thrown an error from a previous redirect
        if ($error = Utilities::getParameterFromRequest($request,'error',false)) {
            $desc = Utilities::getParameterFromRequest($request,'error_description','');
            $desc = $desc !== '' ? " Description: " . $desc : "";
            throw new OpenIDConnectClientException("Error: " . $error .$desc);
        }

        // If we have an authorization code then proceed to request a token
        if ($code = Utilities::getParameterFromRequest($request,'code',false)) {

            $token_json = $this->requestTokens($code, $redirectUri);

            // Throw an error if the server returns one
            if (isset($token_json->error)) {
                if (isset($token_json->error_description)) {
                    throw new OpenIDConnectClientException($token_json->error_description);
                }
                throw new OpenIDConnectClientException('Got response: ' . $token_json->error);
            }

            // Do an OpenID Connect session check
            if (Utilities::getParameterFromRequest($request,'state',false) !== $this->getState()) {
                throw new OpenIDConnectClientException("Unable to determine state");
            }

			// Cleanup state
			$this->unsetState();

            if (!property_exists($token_json, 'id_token')) {
                throw new InvalidReponseType("User did not authorize openid scope.");
            }
            $verification = new JWTVerification();
            $jwk = $this -> configuration -> getJWK();
            $idToken = new IdToken($token_json -> id_token);
            $accessToken = null;
            if($token_json -> access_token){
                $accessToken = new AccessToken($token_json -> access_token);
            }
            try{
                if (!$verification -> verifyJWTsignature($idToken,$jwk,$this -> configuration)) {
                    $this -> log(LogLevel::DEBUG, 'Unable to verify signature',['configuration'=>$this -> configuration,'idToken'=>$idToken,'jwk'=>$jwk]);
                    throw new VerificationException("Unable to verify signature");
                }

                // If this is a valid claim
                if (!$verification->verifyJWTclaims($idToken,$this -> configuration,$this -> getNonce(), $accessToken)) {
                    $this -> log(LogLevel::DEBUG, 'Unable to verify JWT claims',['configuration'=>$this -> configuration,'idToken'=>$idToken,'accessToken'=>$accessToken]);
                    throw new VerificationException("Unable to verify JWT claims");
                }
            }catch(VerificationException $exception){
                $this -> log(LogLevel::DEBUG, 'Unable to verify JWT claims',['configuration'=>$this -> configuration,'idToken'=>$idToken,'accessToken'=>$accessToken,'jwk'=>$jwk]);
                throw new VerificationException("Unable to verify JWT claims",0,$exception);
            }

            // Clean up the session a little
            $this->unsetNonce();

            // Save the id token
            $this->idToken = $idToken;

            // Save the access token
            $this->accessToken = $accessToken;

            // Save the refresh token, if we got one
            if (isset($token_json->refresh_token)){
                $this->refreshToken = new RefreshToken($token_json->refresh_token);
            }
            // Success!
            return true;
        } else {
            $this->requestAuthorization($redirectUri);
            return false;
        }

    }

    /**
     * It calls the end-session endpoint of the OpenID Connect provider to notify the OpenID
     * Connect provider that the end-user has logged out of the relying party site
     * (the client application).
     *
     * @param string $accessToken ID token (obtained at login)
     * @param string $redirect URL to which the RP is requesting that the End-User's User Agent
     * be redirected after a logout has been performed. The value MUST have been previously
     * registered with the OP. Value can be null.
     *
     */
    public function signOut($accessToken, $redirect) {
        $signout_endpoint = $this-> configuration -> getProviderConfigValue("end_session_endpoint");

        $signout_params = null;
        if($redirect == null){
          $signout_params = array('id_token_hint' => $accessToken);
        }
        else {
          $signout_params = array(
                'id_token_hint' => $accessToken,
                'post_logout_redirect_uri' => $redirect);
        }

        $signout_endpoint  .= (strpos($signout_endpoint, '?') === false ? '?' : '&') . http_build_query( $signout_params, null, '&');
        $this->redirect($signout_endpoint);
    }

    /**
     * @param $scope - example: openid, given_name, etc...
     */
    public function addScope($scope) {
        $this->scopes = array_merge($this->scopes, (array)$scope);
    }

    /**
     * @param string $redirectUri
     * @param array $authParams
     * @todo check why authParams is needed here
     */
    private function requestAuthorization($redirectUri,array $authParams = array()) {

        $auth_endpoint = $this-> configuration -> getProviderConfigValue("authorization_endpoint");
        $response_type = "code";

        // Generate and store a nonce in the session
        // The nonce is an arbitrary value
        $nonce = $this->setNonce(Utilities::generateRandString());

        // State essentially acts as a session key for OIDC
        $state = $this->setState(Utilities::generateRandString());

        $auth_params = array_merge($authParams, array(
            'response_type' => $response_type,
            'redirect_uri' => $redirectUri,
            'client_id' => $this -> configuration -> getClientId(),
            'nonce' => $nonce,
            'state' => $state,
            'scope' => 'openid'
        ));

        // If the client has been registered with additional scopes
        if (sizeof($this->scopes) > 0) {
            $auth_params = array_merge($auth_params, array('scope' => implode(' ', $this->scopes)));
        }

        // If the client has been registered with additional response types
        if (sizeof($this->responseTypes) > 0) {
            $auth_params = array_merge($auth_params, array('response_type' => implode(' ', $this->responseTypes)));
        }

        $auth_endpoint .= (strpos($auth_endpoint, '?') === false ? '?' : '&') . http_build_query($auth_params, null, '&');

        $this->redirect($auth_endpoint);
    }

    /**
     * Requests a client credentials token
     *
     */
    public function requestClientCredentialsToken() {
        $token_endpoint = $this-> configuration -> getProviderConfigValue("token_endpoint");

        $headers = [];

        $grant_type = "client_credentials";

        $post_data = array(
            'grant_type'    => $grant_type,
            'client_id'     => $this->configuration -> getClientId(),
            'client_secret' => $this->configuration -> getClientSecret(),
            'scope'         => implode(' ', $this->scopes)
        );

        $response = $this -> httpClient -> sendPost($token_endpoint, $post_data, $headers);
        $body = $response -> getBody();
        $jsonObject = json_decode($body);
        if(null === $jsonObject){
            throw new InvalidReponseType('Json could not be converted from response [%s]',$body);
        }
        return $jsonObject;
    }


    /**
     * Requests a resource owner token
     * (Defined in https://tools.ietf.org/html/rfc6749#section-4.3)
     * 
     * @param $bClientAuth boolean Indicates that the Client ID and Secret be used for client authentication
     */
    public function requestResourceOwnerToken($userName, $password, $bClientAuth =  FALSE) {
        $token_endpoint = $this-> configuration -> getProviderConfigValue("token_endpoint");

        $headers = [];

        $grant_type = "password";

        $post_data = array(
            'grant_type'    => $grant_type,
            'username'      => $userName,
            'password'      => $password,
            'scope'         => implode(' ', $this->scopes)
        );

        //For client authentication include the client values
        if($bClientAuth) {
            $post_data['client_id']     = $this->configuration -> getClientId();
            $post_data['client_secret'] = $this->configuration -> getClientSecret();
        }
        $response = $this -> httpClient -> sendPost($token_endpoint, $post_data, $headers);
        $body = $response -> getBody();
        $jsonObject = json_decode($body);
        if(null === $jsonObject){
            throw new InvalidReponseType('Json could not be converted from response [%s]',$body);
        }
        return $jsonObject;
    }


    /**
     * Requests ID and Access tokens
     *
     * @param $code
     * @param string $redirectUri
     * @return mixed
     */
    private function requestTokens($code, $redirectUri) {
        $token_endpoint = $this-> configuration -> getProviderConfigValue("token_endpoint");
        $token_endpoint_auth_methods_supported = $this-> configuration -> getProviderConfigValue("token_endpoint_auth_methods_supported", ['client_secret_basic']);

        $headers = [];

        $grant_type = "authorization_code";

        $token_params = array(
            'grant_type' => $grant_type,
            'code' => $code,
            'redirect_uri' => $redirectUri,
            'client_id' => $this->configuration -> getClientId(),
            'client_secret' => $this->configuration -> getClientSecret()
        );

        # Consider Basic authentication if provider config is set this way
        if (in_array('client_secret_basic', $token_endpoint_auth_methods_supported)) {
            $headers = ['Authorization: Basic ' . base64_encode($this->configuration -> getClientId() . ':' . $this->configuration -> getClientSecret())];
            unset($token_params['client_secret']);
        }

        $response = $this -> httpClient -> sendPost($token_endpoint, $token_params, $headers);
        $body = $response -> getBody();
        $jsonObject = json_decode($body);
        if(null === $jsonObject){
            throw new InvalidReponseType('Json could not be converted from response [%s]',$body);
        }
        return $jsonObject;
    }

    /**
     * Requests Access token with refresh token
     *
     * @param $code
     * @return RefreshToken
     */
    public function refreshToken($refresh_token) {
        $token_endpoint = $this-> configuration -> getProviderConfigValue("token_endpoint");

        $grant_type = "refresh_token";

        $token_params = array(
            'grant_type' => $grant_type,
            'refresh_token' => $refresh_token,
            'client_id' => $this->configuration -> getClientId(),
            'client_secret' => $this->configuration -> getClientSecret(),
        );

        $response = $this -> httpClient -> sendPost($token_endpoint, $token_params);
        $body = $response -> getBody();
        $jsonObject = json_decode($body);
        if(null === $jsonObject){
            throw new InvalidReponseType('Json could not be converted from response [%s]',$body);
        }
        $this->refreshToken = new RefreshToken($jsonObject->refresh_token);
        return $this->refreshToken;
    }

    /**
     *
     * @param $attribute string optional
     *
     * Attribute        Type    Description
     * user_id            string    REQUIRED Identifier for the End-User at the Issuer.
     * name            string    End-User's full name in displayable form including all name parts, ordered according to End-User's locale and preferences.
     * given_name        string    Given name or first name of the End-User.
     * family_name        string    Surname or last name of the End-User.
     * middle_name        string    Middle name of the End-User.
     * nickname        string    Casual name of the End-User that may or may not be the same as the given_name. For instance, a nickname value of Mike might be returned alongside a given_name value of Michael.
     * profile            string    URL of End-User's profile page.
     * picture            string    URL of the End-User's profile picture.
     * website            string    URL of End-User's web page or blog.
     * email            string    The End-User's preferred e-mail address.
     * verified        boolean    True if the End-User's e-mail address has been verified; otherwise false.
     * gender            string    The End-User's gender: Values defined by this specification are female and male. Other values MAY be used when neither of the defined values are applicable.
     * birthday        string    The End-User's birthday, represented as a date string in MM/DD/YYYY format. The year MAY be 0000, indicating that it is omitted.
     * zoneinfo        string    String from zoneinfo [zoneinfo] time zone database. For example, Europe/Paris or America/Los_Angeles.
     * locale            string    The End-User's locale, represented as a BCP47 [RFC5646] language tag. This is typically an ISO 639-1 Alpha-2 [ISO639‑1] language code in lowercase and an ISO 3166-1 Alpha-2 [ISO3166‑1] country code in uppercase, separated by a dash. For example, en-US or fr-CA. As a compatibility note, some implementations have used an underscore as the separator rather than a dash, for example, en_US; Implementations MAY choose to accept this locale syntax as well.
     * phone_number    string    The End-User's preferred telephone number. E.164 [E.164] is RECOMMENDED as the format of this Claim. For example, +1 (425) 555-1212 or +56 (2) 687 2400.
     * address            JSON object    The End-User's preferred address. The value of the address member is a JSON [RFC4627] structure containing some or all of the members defined in Section 2.4.2.1.
     * updated_time    string    Time the End-User's information was last updated, represented as a RFC 3339 [RFC3339] datetime. For example, 2011-01-03T23:58:42+0000.
     *
     * @return mixed
     *
     */
    public function requestUserInfo($attribute = null) {

        $user_info_endpoint = $this-> configuration -> getProviderConfigValue("userinfo_endpoint");
        $schema = 'openid';

        $user_info_endpoint .= "?schema=" . $schema;

        //The accessToken has to be send in the Authorization header, so we create a new array with only this header.
        $headers = array("Authorization: Bearer {$this->accessToken}");

        $response = $this -> httpClient -> sendGet($user_info_endpoint, $headers);
        $body = $response -> getBody();
        $jsonObject = json_decode($body);
        if(null === $jsonObject){
            throw new InvalidReponseType('Json could not be converted from response [%s]',$body);
        }

        $this->userInfo = $jsonObject;

        if($attribute === null) {
            return $this->userInfo;
        } else if (array_key_exists($attribute, $this->userInfo)) {
            return $this->userInfo->$attribute;
        } else {
            return null;
        }
    }

    /**
     * @param $url
     */
    public function redirect($url) {
        header('Location: ' . $url);
        exit;
    }

    /**
     * Dynamic registration
     * @param ServerRequestInterface $request
     * @param string[] $redirectUris
     * @throws OpenIDConnectClientException
     */
    public function register($clientName, array $redirectUris) {

        $registration_endpoint = $this-> configuration -> getProviderConfigValue('registration_endpoint');

        $send_object = (object)array(
            'redirect_uris' => $redirectUris,
            'client_name' => $clientName
        );

        $response = $this -> httpClient -> sendJsonViaPost($registration_endpoint, json_encode($send_object));
        $body = $response -> getBody();
        $jsonObject = json_decode($body);
        if(null === $jsonObject){
            throw new InvalidReponseType('Json could not be converted from response [%s]',$body);
        }

        // Throw some errors if we encounter them
        if ($jsonObject === false) {
            throw new OpenIDConnectClientException("Error registering: JSON response received from the server was invalid.");
        } elseif (isset($jsonObject->{'error_description'})) {
            throw new OpenIDConnectClientException($jsonObject->{'error_description'});
        }

        // The OpenID Connect Dynamic registration protocol makes the client secret optional
        // and provides a registration access token and URI endpoint if it is not present
        if (!isset($jsonObject->{'client_secret'})) {
            throw new OpenIDConnectClientException("Error registering:
                                                    Please contact the OpenID Connect provider and obtain a Client ID and Secret directly from them");
        }
        $configuration = new ProviderArray(
            $this -> configuration -> getProviderUrl(),
            $jsonObject->{'client_id'},
            $jsonObject->{'client_secret'}

        );
        return $configuration;

    }

    /**
     * Get stored nonce
     *
     * @return string
     */
    protected function getNonce() {
        return $this -> sessionStorage -> get('openid_connect_nonce','');
    }

    /**
     * Stores nonce
     *
     * @param string $nonce
     * @return string
     */
    private function setNonce($nonce) {
        $this -> sessionStorage -> set('openid_connect_nonce',$nonce);
        return $nonce;
    }

    /**
     * Cleanup nonce
     *
     * @return void
     */
    private function unsetNonce() {
        $this -> sessionStorage -> unsetByKey('openid_connect_nonce');
    }

    /**
     * Stores $state
     *
     * @param string $state
     * @return string
     */
    private function setState($state) {
        $this -> sessionStorage -> set('openid_connect_state',$state);
        return $state;
    }

    /**
     * Get stored state
     *
     * @return string
     */
    protected function getState() {
        return $this -> sessionStorage -> get('openid_connect_state','');
    }

    /**
     * Cleanup state
     *
     * @return void
     */
    protected function unsetState() {
        $this -> sessionStorage -> unsetByKey('openid_connect_state');
    }

    private function log($level,$message,array $context = array()){
        if($this -> logger){
            $this -> logger -> log($level,$message,$context);
        }
    }
}
