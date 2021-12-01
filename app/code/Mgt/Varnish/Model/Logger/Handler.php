<?php
/**
 * Copyright © 2017 MGT-Commerce GmbH. All rights reserved.
 *
 * @category    Mgt
 * @package     Mgt_Varnish
 * @copyright   Copyright (c) 2017 (https://www.mgt-commerce.com)
 */

namespace Mgt\Varnish\Model\Logger;

class Handler extends \Magento\Framework\Logger\Handler\Base
{
    /**
     * Detailed debug information
     */
    const DEBUG = 100;

    /**
     * Logging level
     * @var int
     */
    protected $loggerType = 100;

    /**
     * File name
     * @var string
     */
    protected $fileName = '/var/log/mgt_varnish.log';
}