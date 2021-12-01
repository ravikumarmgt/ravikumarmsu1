<?php
/**
 * Copyright © 2017 MGT-Commerce GmbH. All rights reserved.
 *
 * @category    Mgt
 * @package     Mgt_Varnish
 * @copyright   Copyright (c) 2017 (https://www.mgt-commerce.com)
 */

namespace Mgt\Varnish\Model;

class Url extends \Magento\Framework\Model\AbstractModel
{
    /**
     * @var []
     */
    protected $tags = [];

    /**
     * @param \Magento\Framework\Model\Context $context
     * @param \Magento\Framework\Registry $registry
     * @param \Mgt\Varnish\Model\ResourceModel\Url $resource

     */
    public function __construct(
        \Magento\Framework\Model\Context $context,
        \Magento\Framework\Registry $registry,
        \Mgt\Varnish\Model\ResourceModel\Url $resource
    ) {
        parent::__construct($context, $registry, $resource);
    }

    /**
     * {@inheritdoc}
     */
    protected function _construct()
    {
        $this->_init('Mgt\Varnish\Model\ResourceModel\Url');
    }

    /**
     * Loading by store_id and path
     *
     * @param int $storeId
     * @param string $path
     * @return $this
     */
    public function loadByStoreIdAndPath($storeId, $path)
    {
        $resource = $this->_getResource();
        $resource->loadByStoreIdAndPath($this, $storeId, $path);
        return $this;
    }

    /**
     * Get ID
     *
     * @return int
     */
    public function getId()
    {
        return parent::getData('url_id');
    }

    public function setTags(array $tags)
    {
        $this->tags = $tags;
    }

    public function getTags()
    {
        return $this->tags;
    }

    public function afterSave()
    {
        $tags = $this->getTags();
        $resource = $this->_getResource();
        $resource->saveTags($this, $tags);
        return parent::afterSave();
    }
}
