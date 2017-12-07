<?php

namespace WildWolf\OAuth2\Request;

use Psr\Http\Message\ServerRequestInterface;
use WildWolf\OAuth2\Response\ErrorResponse;

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

    private $error;

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

    public function validate()
    {
        $this->error = null;

        $this->validateClientId()
            && $this->validateRedirectUri()
            && $this->validateResponseType()
        ;

        return $this->error ?? true;
    }

    /**
     * @return bool
     */
    protected function validateResponseType() : bool
    {
        if (empty($this->response_type)) {
            $this->error = new ErrorResponse('invalid_request', 'response_type parameter is absent or invalid.');
            return false;
        }

        return true;
    }

    /**
     * @return bool
     */
    protected function validateClientId() : bool
    {
        if (empty($this->client_id)) {
            $this->error = new ErrorResponse('invalid_request', 'client_id parameter is absent or invalid.');
            return false;
        }

        return true;
    }

    /**
     * @param string $uri
     * @return bool
     * @see https://tools.ietf.org/html/rfc6749#section-3.1.2
     */
    protected function validateRedirectUri() : bool
    {
        if (!empty($this->redirect_uri)) {
            $parts = parse_url($this->redirect_uri);
            return
                   $this->isUrlValid($parts)
                && $this->isUrlAbsolute($parts)
                && $this->isFragmentlessUrl($parts)
            ;
        }

        return true;
    }

    private function isUrlValid($parts) : bool
    {
        if (false === $parts) {
            $this->error = new ErrorResponse('invalid_request', 'redirect_uri is not a valid URI.');
            return false;
        }

        return true;
    }

    private function isUrlAbsolute(array $parts) : bool
    {
        // The redirection endpoint URI MUST be an absolute URI
        if (empty($parts['scheme']) || empty($parts['host'])) {
            $this->error = new ErrorResponse('invalid_request', 'redirect_uri is not an absolute URI.');
            return false;
        }

        return true;
    }

    private function isFragmentlessUrl(array $parts) : bool
    {
        // The endpoint URI MUST NOT include a fragment component.
        if (!empty($parts['fragment'])) {
            $this->error = new ErrorResponse('invalid_request', 'redirect_uri must not contain a fragment component.');
            return false;
        }

        return true;
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
