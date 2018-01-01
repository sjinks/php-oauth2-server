<?php

namespace WildWolf\OAuth2\GrantType;

use WildWolf\OAuth2\Interfaces\ClientVerifierInterface;
use WildWolf\OAuth2\Interfaces\TokenGeneratorInterface;

class PasswordGrantTypeHandler extends DefaultGrantTypeHandler
{
    public function __construct(TokenGeneratorInterface $generator, ClientVerifierInterface $verifier = null)
    {
        parent::__construct($generator, $verifier);
        if ($this->verifier === null) {
            throw new \LogicException("ClientVerifierInterface is not provided");
        }
    }
}
