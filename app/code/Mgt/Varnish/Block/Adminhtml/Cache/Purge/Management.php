<?php
/**
 * Copyright © 2017 MGT-Commerce GmbH. All rights reserved.
 *
 * @category    Mgt
 * @package     Mgt_Varnish
 * @copyright   Copyright (c) 2017 (https://www.mgt-commerce.com)
 */

namespace Mgt\Varnish\Block\Adminhtml\Cache\Purge;

class Management extends \Magento\Backend\Block\Template
{
    /**
     * @var \Mgt\Varnish\Model\Cache\Config
     */
    protected $varnishConfig;

    /**
     * @var \Magento\Framework\App\Config
     */
    protected $config;

    /**
     * @param \Magento\Backend\Block\Template\Context $context
     * @param \Magento\Framework\App\Config $config
     * @param \Mgt\Varnish\Model\Cache\Config $varnishConfig
     * @param array $data
     * @SuppressWarnings(PHPMD.ExcessiveParameterList)
     */
    public function __construct(
        \Magento\Backend\Block\Template\Context $context,
        \Magento\Framework\App\Config $config,
        \Mgt\Varnish\Model\Cache\Config $varnishConfig,
        array $data = []
    ) {
        parent::__construct($context, $data);
        $this->config = $config;
        $this->varnishConfig = $varnishConfig;
    }

    public function getWebsites()
    {
        return $this->_storeManager->getWebsites();
    }

    /**
     * Get store groups for specified website
     *
     * @param \Magento\Store\Model\Website $website
     * @return array
     */
    public function getStoreGroups(\Magento\Store\Model\Website $website)
    {
        return $website->getGroups();
    }

    /**
     * Get store views for specified store group
     *
     * @param \Magento\Store\Model\Group $group
     * @return \Magento\Store\Model\Store[]
     */
    public function getStores(\Magento\Store\Model\Group $group)
    {
        $stores = $group->getStores();
        if ($storeIds = $this->getStoreIds()) {
            foreach (array_keys($stores) as $storeId) {
                if (!in_array($storeId, $storeIds)) {
                    unset($stores[$storeId]);
                }
            }
        }
        return $stores;
    }

    public function getStoreBaseUrl(\Magento\Store\Model\Store $store)
    {
        $storeBaseUrl = $this->config->getValue('web/unsecure/base_url', \Magento\Store\Model\ScopeInterface::SCOPE_STORE, $store);
        return $storeBaseUrl;
    }

    public function getStorePurgeUrl(\Magento\Store\Model\Store $store)
    {
        $storePurgeUrl = $this->getUrl('mgtvarnish/purge/action', ['store_id' => $store->getStoreId()]);
        return $storePurgeUrl;
    }

    public function getSinglePurgeActionUrl()
    {
        $singlePurgeActionUrl = $this->getUrl('mgtvarnish/purge/single');
        return $singlePurgeActionUrl;
    }
}