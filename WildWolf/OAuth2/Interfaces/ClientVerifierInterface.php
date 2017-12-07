<?php

namespace WildWolf\OAuth2\Interfaces;

use WildWolf\OAuth2\Request\BaseTokenRequest;
use WildWolf\OAuth2\Response\ErrorResponse;

interface ClientVerifierInterface
{
    public function verifyClient(BaseTokenRequest $request) : bool;
    public function getClientVerificationError() : ErrorResponse;
}
