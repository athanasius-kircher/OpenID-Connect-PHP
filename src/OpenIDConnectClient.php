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
use Athanasius\HttpClient\ClientInterface;
use Athanasius\Session\SessionInterface;
use Athanasius\Exception\OpenIDConnectClientException;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Class OpenIDConnectClient
 * @package Athanasius
 * @todo externalize validation
 * @todo add class representations for tokens
 * @todo implement clean OpenID Spec methods and no aggregation as in authenticate
 * @todo add Unit Tests
 * @todo overwork examples
 */
class OpenIDConnectClient
{
    /**
     * @var string if we aquire an access token it will be stored here
     */
    private $accessToken;

    /**
     * @var string if we aquire a refresh token it will be stored here
     */
    private $refreshToken;

    /**
     * @var string if we acquire an id token it will be stored here
     */
    private $idToken;

    /**
     * @var string stores the token response
     */
    private $tokenResponse;

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
    protected $sessionStorage;
    /**
     * @var ClientInterface
     */
    protected $httpClient;
    /**
     * @var ProviderInterface
     */
    protected $configuration;

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
                throw new OpenIDConnectClientException("User did not authorize openid scope.");
            }

            $claims = $this->decodeJWT($token_json->id_token, 1);

            // Verify the signature
            if ($this->canVerifySignatures()) {
		        if (!$this-> configuration -> getProviderConfigValue('jwks_uri')) {
                    throw new OpenIDConnectClientException ("Unable to verify signature due to no jwks_uri being defined");
                }
                if (!$this->verifyJWTsignature($token_json->id_token)) {
                    throw new OpenIDConnectClientException ("Unable to verify signature");
                }
            } else {
                user_error("Warning: JWT signature verification unavailable.");
            }

            // If this is a valid claim
            if ($this->verifyJWTclaims($claims, $token_json->access_token)) {

                // Clean up the session a little
                $this->unsetNonce();

		        // Save the full response
                $this->tokenResponse = $token_json;

                // Save the id token
                $this->idToken = $token_json->id_token;

                // Save the access token
                $this->accessToken = $token_json->access_token;

                // Save the refresh token, if we got one
                if (isset($token_json->refresh_token)) $this->refreshToken = $token_json->refresh_token;

                // Success!
                return true;

            } else {
                throw new OpenIDConnectClientException ("Unable to verify JWT claims");
            }

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
     * @return mixed
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
        $this->refreshToken = $jsonObject->refresh_token;
        return $jsonObject;
    }

    /**
      * @param array $keys
      * @param array $header
      * @throws OpenIDConnectClientException
      * @return object
      */
     private function get_key_for_header($keys, $header) {
         foreach ($keys as $key) {
             if ($key->kty == 'RSA') {
                 if (!isset($header->kid) || $key->kid == $header->kid) {
                     return $key;
                 }
             } else {
                 if ($key->alg == $header->alg && $key->kid == $header->kid) {
                     return $key;
                 }
             }
         }
         if (isset($header->kid)) {
             throw new OpenIDConnectClientException('Unable to find a key for (algorithm, kid):' . $header->alg . ', ' . $header->kid . ')');
         } else {
             throw new OpenIDConnectClientException('Unable to find a key for RSA');
         }
     }


    /**
     * @param string $hashtype
     * @param object $key
     * @throws OpenIDConnectClientException
     * @return bool
     */
    private function verifyRSAJWTsignature($hashtype, $key, $payload, $signature) {
        if (!class_exists('\phpseclib\Crypt\RSA') && !class_exists('Crypt_RSA')) {
            throw new OpenIDConnectClientException('Crypt_RSA support unavailable.');
        }
        if (!(property_exists($key, 'n') and property_exists($key, 'e'))) {
            throw new OpenIDConnectClientException('Malformed key object');
        }

        /* We already have base64url-encoded data, so re-encode it as
           regular base64 and use the XML key format for simplicity.
        */
        $public_key_xml = "<RSAKeyValue>\r\n".
            "  <Modulus>" . b64url2b64($key->n) . "</Modulus>\r\n" .
            "  <Exponent>" . b64url2b64($key->e) . "</Exponent>\r\n" .
            "</RSAKeyValue>";
	if(class_exists('Crypt_RSA')) {
        	$rsa = new Crypt_RSA();
		$rsa->setHash($hashtype);
        	$rsa->loadKey($public_key_xml, Crypt_RSA::PUBLIC_FORMAT_XML);
        	$rsa->signatureMode = Crypt_RSA::SIGNATURE_PKCS1;
	} else {
		$rsa = new \phpseclib\Crypt\RSA();
		$rsa->setHash($hashtype);
        	$rsa->loadKey($public_key_xml, \phpseclib\Crypt\RSA::PUBLIC_FORMAT_XML);
        	$rsa->signatureMode = \phpseclib\Crypt\RSA::SIGNATURE_PKCS1;
	}
        return $rsa->verify($payload, $signature);
    }
	
    /**
     * @param string $hashtype
     * @param string $key
     * @throws OpenIDConnectClientException
     * @return bool
     */
    private function verifyHMACJWTsignature($hashtype, $key, $payload, $signature)
    {
        if (!function_exists('hash_hmac')) {
            throw new OpenIDConnectClientException('hash_hmac support unavailable.');
        }

        $expected=hash_hmac($hashtype, $payload, $key, true);

        if (function_exists('hash_equals')) {
            return hash_equals($signature, $expected);
        } else {
            return self::hashEquals($signature, $expected);
        }
    }

    /**
     * @param $jwt string encoded JWT
     * @throws OpenIDConnectClientException
     * @return bool
     */
    private function verifyJWTsignature($jwt) {
        $parts = explode(".", $jwt);
        $signature = Utilities::base64urlDecode(array_pop($parts));
        $header = json_decode(Utilities::base64urlDecode($parts[0]));
        $payload = implode(".", $parts);

        $response = $this -> httpClient -> sendGet($this-> configuration -> getProviderConfigValue('jwks_uri'));
        $body = $response -> getBody();
        $jwks = json_decode($body);
        if(null === $jwks){
            throw new InvalidReponseType('Json could not be converted from response [%s]',$body);
        }
        if ($jwks === NULL) {
            throw new OpenIDConnectClientException('Error decoding JSON from jwks_uri');
        }
        $verified = false;
        switch ($header->alg) {
        case 'RS256':
        case 'RS384':
        case 'RS512':
            $hashtype = 'sha' . substr($header->alg, 2);

            $verified = $this->verifyRSAJWTsignature($hashtype,
                                                     $this->get_key_for_header($jwks->keys, $header),
                                                     $payload, $signature);
            break;
	case 'HS256':
        case 'HS512':
        case 'HS384':
            $hashtype = 'SHA' . substr($header->alg, 2);
            $verified = $this->verifyHMACJWTsignature($hashtype, $this -> configuration -> getClientSecret(), $payload, $signature);
            break;		
        default:
            throw new OpenIDConnectClientException('No support for signature type: ' . $header->alg);
        }
        return $verified;
    }

    /**
     * @param object $claims
     * @return bool
     */
    private function verifyJWTclaims($claims, $accessToken = null) {
	if(isset($claims->at_hash) && isset($accessToken)){
            if(isset($this->getAccessTokenHeader()->alg) && $this->getAccessTokenHeader()->alg != 'none'){
                $bit = substr($this->getAccessTokenHeader()->alg, 2, 3);
            }else{
                // TODO: Error case. throw exception???
                $bit = '256';
            }
            $len = ((int)$bit)/16;
            $expecte_at_hash = $this->urlEncode(substr(hash('sha'.$bit, $accessToken, true), 0, $len));
        }
        return (($claims->iss == $this->configuration -> getProviderUrl())
            && (($claims->aud == $this->configuration -> getClientId()) || (in_array($this->configuration -> getClientId(), $claims->aud)))
            && ($claims->nonce == $this->getNonce())
            && ( !isset($claims->exp) || $claims->exp >= time())
            && ( !isset($claims->nbf) || $claims->nbf <= time())
            && ( !isset($claims->at_hash) || $claims->at_hash == $expecte_at_hash )
        );
    }

    /**
     * @param string $str
     * @return string
     */
    protected function urlEncode($str) {
        $enc = base64_encode($str);
        $enc = rtrim($enc, "=");
        $enc = strtr($enc, "+/", "-_");
        return $enc;
    }

    /**
     * @param $jwt string encoded JWT
     * @param int $section the section we would like to decode
     * @return object
     */
    private function decodeJWT($jwt, $section = 0) {

        $parts = explode(".", $jwt);
        return json_decode(Utilities::base64urlDecode($parts[$section]));
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
     * @return bool
     */
    public function canVerifySignatures() {
      return class_exists('\phpseclib\Crypt\RSA') || class_exists('Crypt_RSA');
    }

    /**
     * Set the access token.
     *
     * May be required for subclasses of this Client.
     *
     * @param mixed $accessToken
     *
     * @return void
     */
    public function setAccessToken($accessToken) {
        $this->accessToken = $accessToken;
    }

    /**
     * @return string
     */
    public function getAccessToken() {
        return $this->accessToken;
    }

    /**
     * @return string
     */
    public function getRefreshToken() {
        return $this->refreshToken;
    }

    /**
     * @return string
     */
    public function getIdToken() {
        return $this->idToken;
    }

    /**
     * @return array
     */
    public function getAccessTokenHeader() {
        return $this->decodeJWT($this->accessToken, 0);
    }

    /**
     * @return array
     */
    public function getAccessTokenPayload() {
        return $this->decodeJWT($this->accessToken, 1);
    }

    /**
     * @return array
     */
    public function getIdTokenHeader() {
        return $this->decodeJWT($this->idToken, 0);
    }

    /**
     * @return array
     */
    public function getIdTokenPayload() {
        return $this->decodeJWT($this->idToken, 1);
    }
    /**
     * @return array
     */
    public function getTokenResponse() {
        return $this->tokenResponse;
    }

    /**
     * Stores nonce
     *
     * @param string $nonce
     * @return string
     */
    protected function setNonce($nonce) {
        $this -> sessionStorage -> set('openid_connect_nonce',$nonce);
        return $nonce;
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
     * Cleanup nonce
     *
     * @return void
     */
    protected function unsetNonce() {
        $this -> sessionStorage -> unsetByKey('openid_connect_nonce');
    }

    /**
     * Stores $state
     *
     * @param string $state
     * @return string
     */
    protected function setState($state) {
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
	
    /**
     * Safely calculate length of binary string
     * @param string
     * @return int
     */
    private static function safeLength($str)
    {
        if (function_exists('mb_strlen')) {
            return mb_strlen($str, '8bit');
        }
        return strlen($str);
    }

    /**
     * Where has_equals is not available, this provides a timing-attack safe string comparison
     * @param $str1
     * @param $str2
     * @return bool
     */
    private static function hashEquals($str1, $str2)
    {
        $len1=static::safeLength($str1);
        $len2=static::safeLength($str2);

        //compare strings without any early abort...
        $len = min($len1, $len2);
        $status = 0;
        for ($i = 0; $i < $len; $i++) {
            $status |= (ord($str1[$i]) ^ ord($str2[$i]));
        }
        //if strings were different lengths, we fail
        $status |= ($len1 ^ $len2);
        return ($status === 0);
    }
}
