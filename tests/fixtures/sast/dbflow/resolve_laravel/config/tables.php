<?php
return [
    'audit' => 'audit_log',
    'nested' => ['events' => 'event_rows'],
    'fromenv' => env('ENV_TABLE', 'env_rows'),
];
