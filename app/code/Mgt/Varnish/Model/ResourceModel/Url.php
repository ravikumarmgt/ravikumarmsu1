<?php
/**
 * Copyright © 2017 MGT-Commerce GmbH. All rights reserved.
 *
 * @category    Mgt
 * @package     Mgt_Varnish
 * @copyright   Copyright (c) 2017 (https://www.mgt-commerce.com)
 */

namespace Mgt\Varnish\Model\ResourceModel;

class Url extends \Magento\Framework\Model\ResourceModel\Db\AbstractDb
{
    /**
     * Initialize resource model
     *
     * @return void
     */
    protected function _construct()
    {
        $this->_init('mgt_varnish_url', 'url_id');
    }

    /**
     * Load url by store_id and path
     *
     * @param \Mgt\Varnish\Model\Url $object
     * @param int $storeId
     * @param string $path
     * @return $this
     */
    public function loadByStoreIdAndPath($object, $storeId, $path)
    {
        $connection = $this->getConnection();

        $select = $connection->select()->from(
            ['mgtvu' => $this->getMainTable()]
        )->where(
            'mgtvu.store_id=?',
            $storeId
        )->where(
            'mgtvu.path=?',
            $path
        )->limit(
            1
        );

        $data = $connection->fetchRow($select);

        if ($data) {
            $object->setData($data);
        }
        $this->_afterLoad($object);
        return $this;
    }

    /**
     * Saves Tags
     *
     * @param \Mgt\Varnish\Model\Url $object
     * @param int $storeId
     */
    public function saveTags($object, array $tags)
    {
        if (count($tags)) {
            $connection = $this->getConnection();
            $urlId = $object->getId();
            $data = [];
            foreach ($tags as $tag) {
                $data[] = [
                    'url_id' => $urlId,
                    'tag'    => $tag
                ];
            }
            $tagTable = $this->getTable('mgt_varnish_url_tag');
            $connection->insertMultiple($tagTable, $data);
        }
    }

    public function deleteExpiredUrls()
    {
        $now = new \DateTime('now', new \DateTimeZone('UTC'));
        $now = $now->format('Y-m-d H:i:s');
        $table = $this->getTable('mgt_varnish_url');
        $connection = $this->getConnection();
        $connection->delete(
            $table,
            [
                'cache_expired_at < ?' => $now,
            ]
        );
    }
}
