<?php
namespace App\Http\Controllers;
use App\Models\Invoice;
use App\Models\Receipt;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
class AuditController {
    public function store(Request $request) {
        DB::table(config('tables.audit'))->insert(['msg' => $request->input('msg')]);
        DB::table(config('tables.nested.events'))->insert(['what' => $request->input('what')]);
        DB::table(config('tables.fromenv'))->insert(['ev' => $request->input('ev')]);
        Invoice::create(['memo' => $request->input('memo')]);
        DB::insert("INSERT INTO billing_receipts (note) VALUES ('" . $request->input('note') . "')");
    }
    public function show($id) {
        echo DB::table('audit_log')->where('id', $id)->value('msg');
        echo DB::table('event_rows')->where('id', $id)->value('what');
        echo DB::table('env_rows')->where('id', $id)->value('ev');
        $i = DB::table('billing_invoices')->first();
        echo $i->memo;
        $r = Receipt::find($id);
        echo $r->note;
    }
}
