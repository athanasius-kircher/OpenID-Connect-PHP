<?php

/**
 *
 * Copyright MITRE 2012
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

require "../../autoload.php";

use Athanasius\OpenIDConnectClient;


$request = \Zend\Diactoros\ServerRequestFactory::fromGlobals(
    $_SERVER,
    $_GET,
    $_POST,
    $_COOKIE,
    $_FILES
);

$sessionStorage = new \Athanasius\Session\PHPSessionBridge();
$guzzleClient = new \Athanasius\HttpClient\GuzzleClient();
$configuration = new \Athanasius\Configuration\ProviderAutoDiscover(
    $guzzleClient,
    'http://myproviderURL.com/',
    'ClientIDHere',
    'ClientSecretHere'

);

$oidc = new OpenIDConnectClient(
        $configuration,
        $sessionStorage,
        $guzzleClient
);



$redirectUrl = \Athanasius\Utilities::getCurrentUri($request);//or take your own uri

$oidc->authenticate($request,$redirectUrl);
$name = $oidc->requestUserInfo('given_name');

?>

<html>
<head>
    <title>Example OpenID Connect Client Use</title>
    <style>
        body {
            font-family: 'Lucida Grande', Verdana, Arial, sans-serif;
        }
    </style>
</head>
<body>

    <div>
        Hello <?php echo $name; ?>
    </div>

</body>
</html>

