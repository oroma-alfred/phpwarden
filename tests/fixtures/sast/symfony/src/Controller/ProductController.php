<?php
namespace App\Controller;

use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Process\Process;
use Symfony\Component\Routing\Attribute\Route;

class ProductController
{
    public function __construct(private EntityManagerInterface $em)
    {
    }

    #[Route('/product/{name}')]
    public function show(string $name): Response
    {
        $q = $this->em->createQuery("SELECT p FROM App\\Entity\\Product p WHERE p.name = '" . $name . "'");
        return new Response('<h1>' . $name . '</h1>');
    }

    #[Route('/product/id/{id}')]
    public function byId(int $id): Response
    {
        $q = $this->em->createQuery('SELECT p FROM App\\Entity\\Product p WHERE p.id = ' . $id);
        return new Response('ok');
    }

    #[Route('/ping')]
    public function ping(Request $request): Response
    {
        $host = $request->query->get('host');
        $p = Process::fromShellCommandline('ping -c1 ' . $host);
        $safe = new Process(['ping', '-c1', $host]);
        $n = $request->query->getInt('n');
        $this->em->createQuery('SELECT p FROM App\\Entity\\Product p WHERE p.id = ' . $n);
        return $this->render('ping.html.twig', ['host' => $host]);
    }
}
