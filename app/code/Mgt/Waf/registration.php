<?php

\Magento\Framework\Component\ComponentRegistrar::register(
    \Magento\Framework\Component\ComponentRegistrar::MODULE,
    'Mgt_Waf',
    __DIR__
);

if (false === in_array('phar', \stream_get_wrappers())) {
    stream_wrapper_restore('phar');
}