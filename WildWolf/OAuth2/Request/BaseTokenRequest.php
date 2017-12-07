<?php

namespace WildWolf\OAuth2\Request;

use Psr\Http\Message\ServerRequestInterface;

class BaseTokenRequest
{
    /**
     * @var ServerRequestInterface
     */
    protected $request;

    /**
     * @var string
     */
    protected $grant_type;

    protected $client_id;
    protected $client_secret;

    /**
     * @param ServerRequestInterface $req
     * @return static
     * @see https://tools.ietf.org/html/rfc6749#section-2.3.1
     */
    public static function fromRequest(ServerRequestInterface $req)
    {
        $r = new static();
        return $r->createFromRequest($req);
    }

    protected function createFromRequest(ServerRequestInterface $req)
    {
        $p = $req->getParsedBody();

        $this->request       = $req;
        $this->grant_type    = $p['grant_type']    ?? '';

        // https://tools.ietf.org/html/rfc6749#section-2.3.1
        $this->client_id     = $p['client_id']     ?? null;
        $this->client_secret = $p['client_secret'] ?? null;
        return $this;
    }

    public function validate() : bool
    {
        return
               $this->validateAuthenticationData()
            && !empty($this->grant_type)
        ;
    }

    private function validateAuthenticationData() : bool
    {
        $data = $this->getAuthenticationDataFromServer();
        if ($this->client_secret !== null && !empty($data)) {
            return false;
        }

        if ($this->client_secret !== null && $this->client_id === null) {
            return false;
        }

        return true;
    }

    public function getAuthenticationData() : array
    {
        $data = $this->getAuthenticationDataFromServer();
        if (!empty($data)) {
            return $data;
        }

        if ($this->client_secret !== null && $this->client_id !== null) {
            return [$this->client_id, $this->client_secret];
        }

        return [];
    }

    protected function getAuthenticationDataFromServer() : array
    {
        $params = $this->request->getServerParams();

        if (!empty($params['PHP_AUTH_USER'])) {
            $user = $params['PHP_AUTH_USER'];
            $pass = $params['PHP_AUTH_PW'] ?? '';
            return [$user, $pass];
        }

        $auth = $params['HTTP_AUTHORIZATION']
            ?? ($params['REDIRECT_HTTP_AUTHORIZATION'] ?? self::getAuthFromApache())
        ;

        return self::parseAuthorizationHeader($auth);
    }

    private static function getAuthFromApache()
    {
        $headers = null;
        if (function_exists('apache_request_headers')) {
            $headers = (array)apache_request_headers();
            $headers = array_change_key_case($headers, CASE_UPPER);
        }

        return (isset($headers['AUTHORIZATION'])) ? trim($headers['AUTHORIZATION']) : null;
    }

    private static function parseAuthorizationHeader(string $auth = null) : array
    {
        $m = [];
        if (preg_match('/^basic\\s+(\\S+)/i', $auth, $m)) {
            $auth = explode(':', (string)base64_decode($m[1]), 2);
            if (count($auth) == 2) {
                return $auth;
            }
        }

        return [];
    }

    public function getRequest() : ServerRequestInterface
    {
        return $this->request;
    }

    public function getGrantType() : string
    {
        return $this->grant_type;
    }

    public function getClientId()
    {
        return $this->client_id;
    }

    public function getClientSecret()
    {
        return $this->client_secret;
    }
}
