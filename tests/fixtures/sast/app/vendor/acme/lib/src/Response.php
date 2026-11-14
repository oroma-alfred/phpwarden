<?php
namespace Acme\Lib;

class Response
{
    public function __construct(private string $raw) {}
    public function body(): string { return $this->raw; }
}
