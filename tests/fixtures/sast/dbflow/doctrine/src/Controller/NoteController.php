<?php
namespace App\Controller;
use App\Entity\Note;
use Symfony\Component\HttpFoundation\Request;
class NoteController {
    public function create(Request $request, $em) {
        $n = new Note();
        $n->setBody($request->get('body'));
        $n->setTitle(htmlspecialchars($request->get('title')));
        $em->persist($n);
        $em->flush();
    }
    public function show(Note $n) {
        echo $n->getBody();
        echo $n->getTitle();
    }
}
