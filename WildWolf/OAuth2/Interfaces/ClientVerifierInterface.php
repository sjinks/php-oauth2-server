<?php

namespace WildWolf\OAuth2\Interfaces;

use WildWolf\OAuth2\Request\BaseTokenRequest;
use WildWolf\OAuth2\Response\ErrorResponse;

interface ClientVerifierInterface
{
    /**
     * @param BaseTokenRequest $request
     * @return bool|ErrorResponse
     */
    public function verifyClient(BaseTokenRequest $request);
}
