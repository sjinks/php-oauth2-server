<?php

namespace WildWolf\OAuth2\ResponseType;

use WildWolf\OAuth2\Interfaces\ResponseTypeInterface;
use WildWolf\OAuth2\Request\AuthorizeRequest;
use WildWolf\OAuth2\Interfaces\AuthorizationCodeGeneratorInterface;

class Code implements ResponseTypeInterface
{
    /**
     * @var AuthorizationCodeGeneratorInterface
     */
    protected $generator;

    public function __construct(AuthorizationCodeGeneratorInterface $generator)
    {
        $this->generator = $generator;
    }

    /**
     * {@inheritDoc}
     * @see \WildWolf\OAuth2\Interfaces\ResponseTypeInterface::getRedirectUri()
     * @see https://tools.ietf.org/html/rfc6749#section-4.1.2
     */
    public function getRedirectUri(AuthorizeRequest $request, string $uri) : string
    {
        $code   = $this->generator->generateAuthorizationCode($request);
        $params = ['code' => $code, 'state' => $request->getState()];

        $parts  = parse_url($uri);

        return
              $parts['scheme'] . '://'
            . $parts['host']
            . (isset($parts['port']) ? (':' . $parts['port']) : '')
            . ($parts['path'] ?? '/')
            . '?' . (isset($parts['query']) ? ($parts['query'] . '&') : '')
            . http_build_query($params)
        ;
    }
}
