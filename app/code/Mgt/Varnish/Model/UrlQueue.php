<?php
/**
 * Copyright © 2017 MGT-Commerce GmbH. All rights reserved.
 *
 * @category    Mgt
 * @package     Mgt_Varnish
 * @copyright   Copyright (c) 2017 (https://www.mgt-commerce.com)
 */

namespace Mgt\Varnish\Model;

use Zend\Uri\Uri;

class UrlQueue extends \Magento\Framework\Model\AbstractModel
{
    const PRIORITY_HIGH = 1000;
    const PRIORITY_MEDIUM = 500;
    const PRIORITY_LOW = 100;

    /**
     * @var \Magento\Store\Model\StoreManagerInterface
     */
    protected $storeManager;

    /**
     * @var \Mgt\Varnish\Model\License
     */
    protected $license;

    /**
     * @var []
     */
    protected $licenseCache = [];

    /**
     * @param \Magento\Framework\Model\Context $context
     * @param \Magento\Framework\Registry $registry
     * @param \Mgt\Varnish\Model\ResourceModel\UrlQueue $resource
     * @param \Magento\Store\Model\StoreManagerInterface $storeManager
     * @param \Mgt\Varnish\Model\License $license
     */
    public function __construct(
        \Magento\Framework\Model\Context $context,
        \Magento\Framework\Registry $registry,
        \Mgt\Varnish\Model\ResourceModel\UrlQueue $resource,
        \Magento\Store\Model\StoreManagerInterface $storeManager,
        \Mgt\Varnish\Model\License $license
    ) {
        parent::__construct($context, $registry, $resource);
        $this->storeManager = $storeManager;
        $this->license = $license;
    }

    /**
     * {@inheritdoc}
     */
    protected function _construct()
    {
        $this->_init('Mgt\Varnish\Model\ResourceModel\UrlQueue');
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

    public function addToQueue(array $urls)
    {
        $urls = $this->filterUrls($urls);
        if ($urls) {
            $resource = $this->_getResource();
            $resource->addToQueue($urls);
        }
    }

    protected function filterUrls(array $urls)
    {
        $filteredUrls = [];
        foreach ($urls as $url) {
            $storeId = (int)$url['store_id'];
            $url['path'] = ltrim($url['path'], '/');
            $canAddUrlToQueue = $this->canAddUrlToQueue($storeId);
            if (true === $canAddUrlToQueue) {
                $filteredUrls[] = $url;
            }
        }
        return $filteredUrls;
    }

    protected function canAddUrlToQueue($storeId)
    {
        if (isset($this->licenseCache[$storeId])) {
            $canAddUrlToQueue = $this->licenseCache[$storeId];
            return $canAddUrlToQueue;
        } else {
            $store = $this->storeManager->getStore($storeId);
            $uri = new Uri($store->getBaseUrl());
            $host = $uri->getHost();
            $hasLicense = $this->license->hasLicense($host);
            $this->licenseCache[$storeId] = $hasLicense;
            if (true === $hasLicense) {
                return true;
            } else {
                return false;
            }
        }
    }
}
