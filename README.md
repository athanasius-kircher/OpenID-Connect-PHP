PHP OpenID Connect Basic Client
========================
A simple library that allows an application to authenticate a user through the basic OpenID Connect flow.
This library hopes to encourage OpenID Connect use by making it simple enough for a developer with little knowledge of
the OpenID Connect protocol to setup authentication.

A special thanks goes to Justin Richer and Amanda Anganes for their help and support of the protocol.

# Requirements #
 1. PHP 5.6 or greater
 2. JSON extension

## Install ##
 1. Install library using composer
```
composer require jumbojett/openid-connect-php
```
 2. Include composer autoloader
```php
require '/vendor/autoload.php';
```

## Example 1: Basic Client ##

```php
use Jumbojett\OpenIDConnectClient;
$request = \Zend\Diactoros\ServerRequestFactory::fromGlobals(
    $_SERVER,
    $_GET,
    $_POST,
    $_COOKIE,
    $_FILES
);


$redirectUrl = \Jumbojett\Utilities::getCurrentUri($request);//or take your own uri
$sessionStorage = new \Jumbojett\PHPSessionBridge();

$guzzleClient = new GuzzleHttp\Client();

$oidc = new OpenIDConnectClient(
        $sessionStorage,
        $guzzleClient,
        'https://id.provider.com',
        'ClientIDHere',
        'ClientSecretHere'
        );
$oidc->setCertPath('/path/to/my.cert');
$oidc->authenticate($request,$redirectUrl);
$name = $oidc->requestUserInfo('given_name');

```

[See openid spec for available user attributes][1]

## Example 2: Dynamic Registration ##

```php
use Jumbojett\OpenIDConnectClient;
$request = \Zend\Diactoros\ServerRequestFactory::fromGlobals(
    $_SERVER,
    $_GET,
    $_POST,
    $_COOKIE,
    $_FILES
);
$sessionStorage = new \Jumbojett\PHPSessionBridge();
$redirectUrls = [\Jumbojett\Utilities::getCurrentUri($request)];//or take your own uri
$guzzleClient = new GuzzleHttp\Client();

$oidc = new OpenIDConnectClient(
        $sessionStorage,
        $guzzleClient,
        $sessionStorage,
        "https://id.provider.com"
);

$oidc->register($request,$redirectUrls);
$client_id = $oidc->getClientID();
$client_secret = $oidc->getClientSecret();

// Be sure to add logic to store the client id and client secret
```

## Example 3: Network and Security ##
```php
// Configure a proxy
$oidc->setHttpProxy("http://my.proxy.com:80/");

// Configure a cert
$oidc->setCertPath("/path/to/my.cert");
```

## Example 4: Request Client Credentials Token ##

```php
use Jumbojett\OpenIDConnectClient;

$sessionStorage = new \Jumbojett\PHPSessionBridge();

$guzzleClient = new GuzzleHttp\Client();

$oidc = new OpenIDConnectClient(
        $sessionStorage,
        $guzzleClient,
        'https://id.provider.com',
        'ClientIDHere',
        'ClientSecretHere');
$oidc->providerConfigParam(array('token_endpoint'=>'https://id.provider.com/connect/token'));
$oidc->addScope('my_scope');

// this assumes success (to validate check if the access_token property is there and a valid JWT) :
$clientCredentialsToken = $oidc->requestClientCredentialsToken()->access_token;

```

## Example 5: Request Resource Owners Token (with client auth) ##

```php
use Jumbojett\OpenIDConnectClient;

$sessionStorage = new \Jumbojett\PHPSessionBridge();

$guzzleClient = new GuzzleHttp\Client();

$oidc = new OpenIDConnectClient(
        $sessionStorage,
        $guzzleClient,
        'https://id.provider.com',
        'ClientIDHere',
        'ClientSecretHere');
$oidc->providerConfigParam(array('token_endpoint'=>'https://id.provider.com/connect/token'));
$oidc->addScope('my_scope');

//Add username and password
$oidc->addAuthParam(array('username'=>'<Username>'));
$oidc->addAuthParam(array('password'=>'<Password>'));

//Perform the auth and return the token (to validate check if the access_token property is there and a valid JWT) :
$token = $oidc->requestResourceOwnerToken(TRUE)->access_token;

```


## Development Environments ##
In some cases you may need to disable SSL security on on your development systems.
Note: This is not recommended on production systems.

```php
$oidc->setVerifyHost(false);
$oidc->setVerifyPeer(false);
```

### Todo ###
- Dynamic registration does not support registration auth tokens and endpoints

  [1]: http://openid.net/specs/openid-connect-basic-1_0-15.html#id_res
  
## Contributing ###
 - All pull requests, once merged, should be added to the changelog.md file.
