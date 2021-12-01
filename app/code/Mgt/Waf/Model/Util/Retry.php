<?php

namespace Mgt\Waf\Model\Util;

class Retry
{
    static public function retry(callable $fn, $retries = 2, $delay = 3)
    {
        beginning:
        try {
            return $fn();
        } catch (\Exception $e) {
            if (!$retries) {
                throw $e;
            }
            $retries--;
            if ($delay) {
                sleep($delay);
            }
            goto beginning;
        }
    }
}