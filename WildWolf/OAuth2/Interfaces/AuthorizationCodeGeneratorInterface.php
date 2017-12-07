<?php

namespace WildWolf\OAuth2\Interfaces;

use WildWolf\OAuth2\Request\AuthorizeRequest;

interface AuthorizationCodeGeneratorInterface
{
    public function generateAuthorizationCode(AuthorizeRequest $request) : string;
}
