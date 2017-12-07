<?php

namespace WildWolf\OAuth2\Interfaces;

use WildWolf\OAuth2\Request\AuthorizeRequest;

interface ResponseTypeInterface
{
    public function getRedirectUri(AuthorizeRequest $request, string $uri) : string;
}
