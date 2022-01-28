<?php

namespace JWT\algorithms;

use stdClass;

function encode(string|array|stdClass $data): string {
    return rtrim(urlencode(base64_encode(json_encode($data))), "=");
}

function decode(string $data): string|array|stdClass {
    $needsPadding = strlen($data) % 4;

    if ($needsPadding) {
        $paddingSize = 4 - $needsPadding;
        $data .= str_repeat("=", $paddingSize);
    }

    return json_decode(base64_decode(urldecode($data)));
}
