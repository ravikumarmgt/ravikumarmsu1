<?php
/**
 * Copyright © 2017 MGT-Commerce GmbH. All rights reserved.
 *
 * @category    Mgt
 * @package     Mgt_Varnish
 * @copyright   Copyright (c) 2017 (https://www.mgt-commerce.com)
 */

namespace Mgt\Varnish\Model\Observer;

use Magento\Framework\Event\ObserverInterface;

class InvalidateObserver implements ObserverInterface
{
    /**
     * Config
     *
     * @var \Magento\PageCache\Model\Config
     */
    protected $config;

    /**
     * @var \Magento\CacheInvalidate\Model\PurgeCache
     */
    protected $purgeCache;

    /**
     * @param \Magento\PageCache\Model\Config $config
     * @param \Magento\CacheInvalidate\Model\PurgeCache $purgeCache
     */
    public function __construct(
        \Magento\PageCache\Model\Config $config,
        \Magento\CacheInvalidate\Model\PurgeCache $purgeCache
    ) {
        $this->config = $config;
        $this->purgeCache = $purgeCache;
    }

    /**
     * If Varnish caching is enabled it collects array of tags
     * of incoming object and asks to clean cache.
     *
     * @param \Magento\Framework\Event\Observer $observer
     * @return void
     */
    public function execute(\Magento\Framework\Event\Observer $observer)
    {
        $cacheType = $this->config->getType();
        $isFpcEnabled = $this->config->isEnabled();
        if ($cacheType == \Magento\PageCache\Model\Config::VARNISH && true === $isFpcEnabled) {
            $object = $observer->getEvent()->getObject();
            if ($object instanceof \Magento\Framework\DataObject\IdentityInterface) {
                $tags = $object->getIdentities();
                if (count($tags)) {
                    $this->purgeCache->sendPurgeRequest($tags);
                }
            }
        }
    }
}
