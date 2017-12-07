<?php

namespace WildWolf\OAuth2\Request;

use Psr\Http\Message\ServerRequestInterface;

class AuthorizeRequest
{
    /**
     * @var ServerRequestInterface
     */
    protected $request;

    /**
     * @var string|null
     */
    protected $response_type;

    /**
     * @var string|null
     */
    protected $client_id;

    /**
     * @var string|null
     */
    protected $redirect_uri;

    /**
     * @var string|null
     */
    protected $scope;

    /**
     * @var string|null
     */
    protected $state;

    public static function fromServerRequest(ServerRequestInterface $request) : AuthorizeRequest
    {
        $params = $request->getQueryParams();
        $result = new self();

        $result->request       = $request;
        $result->response_type = $params['response_type'] ?? null;
        $result->client_id     = $params['client_id']     ?? null;
        $result->redirect_uri  = $params['redirect_uri']  ?? null;
        $result->scope         = $params['scope']         ?? null;
        $result->state         = $params['state']         ?? null;

        $result->fixUpResponseType();
        return $result;
    }

    /*
     * Extension response types MAY contain a space-delimited (%x20) list of
     * values, where the order of values does not matter (e.g., response
     * type "a b" is the same as "b a").  The meaning of such composite
     * response types is defined by their respective specifications.
     */
    private function fixUpResponseType()
    {
        if (false !== strpos($this->response_type, ' ')) {
            $rt = explode(' ', $this->response_type);
            sort($rt);
            $this->response_type = join(' ', $rt);
        }
    }

    public function getRequest() : ServerRequestInterface
    {
        return $this->request;
    }

    public function getResponseType()
    {
        return $this->response_type;
    }

    public function getClientId()
    {
        return $this->client_id;
    }

    public function getRedirectUri()
    {
        return $this->redirect_uri;
    }

    public function getScope()
    {
        return $this->scope;
    }

    public function getState()
    {
        return $this->state;
    }
}
