<?php

namespace WildWolf\OAuth2\Interfaces;

use WildWolf\OAuth2\Request\AuthorizeRequest;
use WildWolf\OAuth2\Response\BaseResponse;

interface ImplicitGrantAccessTokenGeneratorInterface
{
    public function generateImplicitGrantAccessToken(AuthorizeRequest $request) : BaseResponse;
}
