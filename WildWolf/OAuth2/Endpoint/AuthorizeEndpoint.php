<?php

namespace WildWolf\OAuth2\Endpoint;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use WildWolf\OAuth2\Request\AuthorizeRequest;
use WildWolf\OAuth2\Interfaces\AuthorizerInterface;
use WildWolf\OAuth2\Response\ErrorResponse;
use WildWolf\OAuth2\Interfaces\ResponseTypeInterface;
use WildWolf\OAuth2\Interfaces\AuthorizeEndpointInterface;

class AuthorizeEndpoint implements AuthorizeEndpointInterface
{
    /**
     * @var AuthorizeRequest
     */
    protected $authRequest;

    /**
     * @var AuthorizerInterface
     */
    protected $authorizer;

    /**
     * @var ErrorResponse
     */
    protected $error = null;

    /**
     * @var ResponseTypeInterface[]
     */
    protected $rt_handlers = [];

    public function initialize(ServerRequestInterface $request, AuthorizerInterface $authorizer, array $handlers)
    {
        $this->authRequest = AuthorizeRequest::fromServerRequest($request);
        $this->authorizer  = $authorizer;
        $this->rt_handlers = $handlers;
    }

    public function getError(ResponseInterface $response) : ResponseInterface
    {
        return $this->error
            ? $this->error($response, $this->error, $this->authorizer->getRedirectUri())
            : $response
        ;
    }

    private function error(ResponseInterface $response, ErrorResponse $e, string $uri) : ResponseInterface
    {
        $state = $this->authRequest->getState();
        $extra = $state ? ['state' => $state] : [];
        return $e->toResponseInterface($response, $extra, $uri);
    }

    public function handleAuthorizeRequest(ResponseInterface $response, bool $deny = false) : ResponseInterface
    {
        if (!$this->validateRequest()) {
            return $this->error($response, /** @scrutinizer ignore-type */ $this->error, $this->authorizer->getRedirectUri());
        }

        $uri = $this->authorizer->getRedirectUri();
        if ($deny) {
            $this->error = new ErrorResponse('access_denied', 'The user or authorization server denied the request.');
            return $this->error($response, $this->error, $uri);
        }

        $handler = $this->rt_handlers[$this->authRequest->getResponseType()];
        $uri     = $handler->getRedirectUri($this->authRequest, $uri);

        return $response
            ->withStatus(302)
            ->withHeader('Location', $uri)
            ->withHeader('Pragma', 'no-cache')
        ;
    }

    /**
     * @return bool
     */
    public function validateRequest() : bool
    {
        $this->error = null;
        $this->authorizer->initializeAuthorizer($this->authRequest);

        $res =
               $this->validateClientId($this->authRequest->getClientId())
            && $this->validateRedirectUri($this->authRequest->getRedirectUri())
            && $this->validateResponseType($this->authRequest->getResponseType())
        ;

        if (false === $res) {
            return $res;
        }

        if (!$this->authorizer->validateAuthorizeRequest()) {
            $res = false;
            $this->error = $this->authorizer->getAuthorizerValidationError();
        }

        return $res;
    }

    /**
     * @param string $rt
     * @return bool
     * @see https://tools.ietf.org/html/rfc6749#section-3.1.1
     */
    protected function validateResponseType(string $rt = null) : bool
    {
        if (empty($rt)) {
            $this->error = new ErrorResponse('invalid_request', 'response_type parameter is absent or invalid.');
            return false;
        }

        if (!isset($this->rt_handlers[$rt])) {
            $this->error = new ErrorResponse(
                'unsupported_response_type',
                sprintf('The authorization server does not support obtaining an authorization code using method "%s".', $rt)
            );

            return false;
        }

        return true;
    }

    /**
     * @param string $cid
     * @return bool
     */
    protected function validateClientId(string $cid = null) : bool
    {
        if (empty($cid)) {
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
    protected function validateRedirectUri(string $uri = null) : bool
    {
        if (!empty($uri)) {
            $parts = parse_url($uri);
            if (false === $parts) {
                $this->error = new ErrorResponse('invalid_request', 'redirect_uri is not a valid URI.');
                return false;
            }

            // The redirection endpoint URI MUST be an absolute URI
            if (empty($parts['scheme']) || empty($parts['host'])) {
                $this->error = new ErrorResponse('invalid_request', 'redirect_uri is not an absolute URI.');
                return false;
            }

            // The endpoint URI MUST NOT include a fragment component.
            if (!empty($parts['fragment'])) {
                $this->error = new ErrorResponse('invalid_request', 'redirect_uri must not contain a fragment component.');
                return false;
            }
        }

        return true;
    }
}
