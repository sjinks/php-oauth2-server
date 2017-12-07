<?php

namespace WildWolf\OAuth2\Interfaces;

use WildWolf\OAuth2\Request\AuthorizeRequest;
use WildWolf\OAuth2\Response\ErrorResponse;

interface AuthorizerInterface
{
    public function initializeAuthorizer(AuthorizeRequest $request);
    public function validateAuthorizeRequest() : bool;
    public function getRedirectUri() : string;
    public function getAuthorizerValidationError() : ErrorResponse;
}
