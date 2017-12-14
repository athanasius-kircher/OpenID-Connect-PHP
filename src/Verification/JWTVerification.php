<?php
/**
 * Created by PhpStorm.
 * User: boellmann
 * Date: 14.12.2017
 * Time: 22:40
 */

namespace Athanasius\Verification;


use Athanasius\Configuration\ProviderInterface;
use Athanasius\Exception\VerificationException;
use Athanasius\Token\AccessToken;
use Athanasius\Token\IdToken;
use Athanasius\Utilities;

class JWTVerification
{
    /**
     * @param IdToken $idToken
     * @param JWK $jwk
     * @param ProviderInterface $configuration
     * @return bool
     * @throws VerificationException
     */
    public function verifyJWTsignature(IdToken $idToken,JWK $jwk,ProviderInterface $configuration) {
        $signature = $idToken -> getSignature();
        $header = $idToken -> getHeader();
        $payload = $idToken -> getPayloadStringWithHeader();
        switch ($header->alg) {
            case 'RS256':
            case 'RS384':
            case 'RS512':
                $hashtype = 'sha' . substr($header->alg, 2);
                $verified = $this->verifyRSAJWTsignature(
                    $hashtype,
                    $this->getKeyByHeader($jwk->getKeys(), $header),
                    $payload, $signature);
                break;
            case 'HS256':
            case 'HS512':
            case 'HS384':
                $hashtype = 'SHA' . substr($header->alg, 2);
                $verified = $this->verifyHMACJWTsignature(
                    $hashtype,
                    $configuration -> getClientSecret(),
                    $payload,
                    $signature
                );
                break;
            default:
                throw new VerificationException('No support for signature type: ' . $header->alg);
        }
        return $verified;
    }

    /**
     * @param IdToken $idToken
     * @param ProviderInterface $configuration
     * @param string $nonce
     * @param AccessToken|null $accessToken
     * @return bool
     */
    public function verifyJWTclaims(IdToken $idToken,ProviderInterface $configuration,$nonce,AccessToken $accessToken = null) {
        $claims = $idToken -> getPayload();
        $expecte_at_hash = '';
        if(isset($claims->at_hash) && isset($accessToken)){
            if(isset($accessToken -> getHeader() -> alg) && $accessToken -> getHeader() -> alg != 'none'){
                $bit = substr($accessToken -> getHeader() -> alg, 2, 3);
            }else{
                // TODO: Error case. throw exception???
                $bit = '256';
            }
            $len = ((int)$bit)/16;
            $expecte_at_hash = $this->urlEncode(substr(hash('sha'.$bit, $accessToken -> getTokenString(), true), 0, $len));
        }
        return (($claims->iss == $configuration -> getProviderUrl())
            && (($claims->aud == $configuration -> getClientId()) || (in_array($configuration -> getClientId(), $claims->aud)))
            && ($claims->nonce == $nonce)
            && ( !isset($claims->exp) || $claims->exp >= time())
            && ( !isset($claims->nbf) || $claims->nbf <= time())
            && ( !isset($claims->at_hash) || $claims->at_hash == $expecte_at_hash )
        );
    }

    /**
     * @param array $keys
     * @param array $header
     * @throws VerificationException
     * @return object
     */
    private function getKeyByHeader($keys, $header) {
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
            throw new VerificationException('Unable to find a key for (algorithm, kid):' . $header->alg . ', ' . $header->kid . ')');
        } else {
            throw new VerificationException('Unable to find a key for RSA');
        }
    }


    /**
     * @param string $hashtype
     * @param object $key
     * @throws VerificationException
     * @return bool
     */
    private function verifyRSAJWTsignature($hashtype, $key, $payload, $signature) {
        if (!(property_exists($key, 'n') and property_exists($key, 'e'))) {
            throw new VerificationException('Malformed key object');
        }
        /* We already have base64url-encoded data, so re-encode it as
           regular base64 and use the XML key format for simplicity.
        */
        $public_key_xml = "<RSAKeyValue>\r\n".
            "  <Modulus>" . Utilities::b64url2b64($key->n) . "</Modulus>\r\n" .
            "  <Exponent>" . Utilities::b64url2b64($key->e) . "</Exponent>\r\n" .
            "</RSAKeyValue>";
        $rsa = new \phpseclib\Crypt\RSA();
        $rsa->setHash($hashtype);
        $rsa->loadKey(
            $public_key_xml,
            \phpseclib\Crypt\RSA::PUBLIC_FORMAT_XML
        );
        $rsa->signatureMode = \phpseclib\Crypt\RSA::SIGNATURE_PKCS1;
        return $rsa->verify($payload, $signature);
    }

    /**
     * @param string $hashtype
     * @param string $key
     * @return bool
     */
    private function verifyHMACJWTsignature($hashtype, $key, $payload, $signature)
    {
        $expected=hash_hmac($hashtype, $payload, $key, true);
        return hash_equals($signature, $expected);
    }

    /**
     * @param string $str
     * @return string
     */
    private function urlEncode($str) {
        $enc = base64_encode($str);
        $enc = rtrim($enc, "=");
        $enc = strtr($enc, "+/", "-_");
        return $enc;
    }
}