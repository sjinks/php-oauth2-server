<?php

namespace WildWolf\OAuth2\Response;

class ErrorResponse extends BaseResponse
{
    protected $error;
    protected $error_description;
    protected $error_uri;

    public function __construct(string $error, string $desc = null, string $uri = null)
    {
        $this->setStatusCode(400);

        $this->error             = $error;
        $this->error_description = $desc;
        $this->error_uri         = $uri;
    }

    public function toArray() : array
    {
        $r = ['error' => $this->error];

        if ($this->error_description !== null) {
            $r['error_description'] = $this->error_description;
        }

        if ($this->error_uri !== null) {
            $r['error_uri'] = $this->error_uri;
        }

        return $r;
    }

    public function getError() : string
    {
        return $this->error;
    }

    public function getErrorDescription() : string
    {
        return (string)$this->error_description;
    }

    public function getErrorUri() : string
    {
        return (string)$this->getErrorUri();
    }
}
