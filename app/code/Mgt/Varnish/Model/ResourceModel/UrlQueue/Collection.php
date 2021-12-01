<?php
/**
 * Copyright © 2017 MGT-Commerce GmbH. All rights reserved.
 *
 * @category    Mgt
 * @package     Mgt_Varnish
 * @copyright   Copyright (c) 2017 (https://www.mgt-commerce.com)
 */

namespace Mgt\Varnish\Model\ResourceModel\UrlQueue;

class Collection extends \Mgt\Varnish\Model\ResourceModel\AbstractCollection
{
    /**
     * Resource initialization
     *
     * @return void
     */
    protected function _construct()
    {
        $this->_init('Mgt\Varnish\Model\UrlQueue', 'Mgt\Varnish\Model\ResourceModel\UrlQueue');
    }
}
