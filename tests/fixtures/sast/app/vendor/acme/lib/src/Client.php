<?php
namespace Acme\Lib;

class Client
{
    public function send(string $q): Response
    {
        return new Response($q);
    }
}
