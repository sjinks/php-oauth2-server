<?php

namespace WildWolf\OAuth2\Interfaces;

use WildWolf\OAuth2\Request\BaseTokenRequest;
use WildWolf\OAuth2\Response\BaseResponse;

interface GrantTypeInterface
{
    public function generateAccessToken(BaseTokenRequest $request) : BaseResponse;
}
