<?php
namespace App\Controller;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;
use Doctrine\ORM\EntityManagerInterface;
class ArticleController
{
    public function __construct(private EntityManagerInterface $em) {}
    #[Route('/article/new', methods: ['POST'])]
    public function create(): Response { $a = new Article(); $this->em->persist($a); $this->em->flush(); }
    #[Route('/article/delete', methods: ['POST'])]
    #[IsGranted('ROLE_ADMIN')]
    public function delete(): Response { $this->em->remove($this->em->find(Article::class, 1)); $this->em->flush(); }
}
