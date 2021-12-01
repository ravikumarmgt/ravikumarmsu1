<?php
/**
 * Copyright © 2017 MGT-Commerce GmbH. All rights reserved.
 *
 * @category    Mgt
 * @package     Mgt_Varnish
 * @copyright   Copyright (c) 2017 (https://www.mgt-commerce.com)
 */

namespace Mgt\Varnish\Model\ResourceModel\UrlRewrite;

class UrlRewriteCollection extends \Magento\UrlRewrite\Model\ResourceModel\UrlRewriteCollection
{
    public function addStoreFilter($store, $withAdmin = true)
    {
        if (!is_array($store)) {
            $store = [$this->storeManager->getStore($store)->getId()];
        }
        if ($withAdmin) {
            $store[] = 0;
        }
        $this->addFieldToFilter('main_table.store_id', ['in' => $store]);
        return $this;
    }

    public function addEntityTypeFilter($entityType)
    {
        $this->addFieldToFilter('main_table.entity_type', $entityType);
        return $this;
    }

    public function addEntityIdFilter(array $entities)
    {
        $this->addFieldToFilter('main_table.entity_id', ['in' => $entities]);
        return $this;
    }
}