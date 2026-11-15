<?php
namespace App\Models;
use Illuminate\Database\Eloquent\Model;
class Invoice extends Model {
    const TABLE = 'billing_invoices';
    protected $table = self::TABLE;
}
