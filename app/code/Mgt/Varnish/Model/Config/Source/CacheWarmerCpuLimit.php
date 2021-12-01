<?php
/**
 * Copyright © 2017 MGT-Commerce GmbH. All rights reserved.
 *
 * @category    Mgt
 * @package     Mgt_Varnish
 * @copyright   Copyright (c) 2017 (https://www.mgt-commerce.com)
 */

namespace Mgt\Varnish\Model\Config\Source;

class CacheWarmerCpuLimit implements \Magento\Framework\Option\ArrayInterface
{
    /**
     * Options getter
     *
     * @return array
     */
    public function toOptionArray()
    {
        $optionsArray = [];
        foreach(range(10, 90, 10) as $number) {
            $optionsArray[]= ['value' => $number, 'label' => $number];
        }
        return $optionsArray;
    }

    /**
     * Get options in "key-value" format
     *
     * @return array
     */
    public function toArray()
    {
        $optionsArray = [];
        foreach(range(10, 90, 10) as $number) {
            $optionsArray[$number]= $number;
        }
        return $optionsArray;
    }
}