<?php
/**
 * Copyright © 2017 MGT-Commerce GmbH. All rights reserved.
 *
 * @category    Mgt
 * @package     Mgt_Varnish
 * @copyright   Copyright (c) 2017 (https://www.mgt-commerce.com)
 */

namespace Mgt\Varnish\Model\ResourceModel;

class UrlQueue extends \Magento\Framework\Model\ResourceModel\Db\AbstractDb
{
    /**
     * Initialize resource model
     *
     * @return void
     */
    protected function _construct()
    {
        $this->_init('mgt_varnish_url_queue', 'url_id');
    }

    public function addToQueue(array $urls)
    {
        $table = $this->getTable('mgt_varnish_url_queue');
        $fields = ['store_id', 'path', 'priority'];
        $connection = $this->getConnection();
        $connection->insertOnDuplicate($table, $urls, $fields);
    }

    public function deleteFromQueue(array $urlIds)
    {
        $table = $this->getTable('mgt_varnish_url_queue');
        $connection = $this->getConnection();
        $connection->delete($table, ['url_id IN(?)' => $urlIds]);
    }

    public function flushAll()
    {
        $table = $this->getTable('mgt_varnish_url_queue');
        $connection = $this->getConnection();
        $connection->delete($table, []);
    }
}