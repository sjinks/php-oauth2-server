<?php

namespace WildWolf\OAuth2\GrantType;

use WildWolf\OAuth2\Request\BaseTokenRequest;
use WildWolf\OAuth2\Response\BaseResponse;
use WildWolf\OAuth2\Interfaces\ClientVerifierInterface;
use WildWolf\OAuth2\Interfaces\TokenGeneratorInterface;
use WildWolf\OAuth2\Interfaces\GrantTypeInterface;

class DefaultGrantTypeHandler implements GrantTypeInterface
{
    /**
     * @var TokenGeneratorInterface
     */
    protected $generator;

    /**
     * @var ClientVerifierInterface|null
     */
    protected $verifier;

    public function __construct(TokenGeneratorInterface $generator, ClientVerifierInterface $verifier = null)
    {
        $this->generator = $generator;

        if ($verifier === null) {
            if ($generator instanceof ClientVerifierInterface) {
                $this->verifier = $generator;
            }
        }
        else {
            $this->verifier = $verifier;
        }
    }

    public function generateAccessToken(BaseTokenRequest $request) : BaseResponse
    {
        if ($this->verifier) {
            $res = $this->verifier->verifyClient($request);
            if (true !== $res) {
                return $res;
            }
        }

        return $this->generator->generateAccessToken($request);
    }
}
