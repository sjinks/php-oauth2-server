<?php

namespace WildWolf\OAuth2\Interfaces;

use WildWolf\OAuth2\Response\BaseResponse;
use WildWolf\OAuth2\Request\BaseTokenRequest;

interface TokenGeneratorInterface
{
    public function generateAccessToken(BaseTokenRequest $req) : BaseResponse;
}
