<?php
namespace App\Entity;
class Note {
    private $body;
    private $title;
    public function getBody() { return $this->body; }
    public function setBody($b) { $this->body = $b; }
    public function getTitle() { return $this->title; }
    public function setTitle($t) { $this->title = $t; }
}
