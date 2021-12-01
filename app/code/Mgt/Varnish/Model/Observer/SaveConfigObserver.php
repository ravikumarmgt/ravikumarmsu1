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
use Magento\Framework\Event\Observer;

class SaveConfigObserver implements ObserverInterface
{
    const FULL_PAGE_CACHE_STATUS_ENABLED = 1;
    const FULL_PAGE_CACHE_STATUS_DISABLED = 0;

    /**
     * @var \Mgt\Varnish\Model\Cache\Config
     */
    protected $config;

    /**
     * @var \Magento\Framework\App\DeploymentConfig\Writer
     */
    protected $deploymentConfigWriter;

    /**
     * @var \Magento\Framework\App\Config\ValueFactory
     */
    protected $configValueFactory;

    /**
     * @var \Magento\CacheInvalidate\Model\PurgeCache
     */
    protected $cachePurger;

    /**
     * @var \Magento\Framework\App\Cache\TypeListInterface
     */
    protected $cacheTypeList;

    /**
     * @param \Mgt\Varnish\Model\Cache\Config $config
     * @param \Magento\Framework\App\DeploymentConfig\Writer $deploymentConfigWriter
     * @param \Magento\Framework\App\Config\ValueFactory $configValueFactory
     * @param \Magento\CacheInvalidate\Model\PurgeCache $cachePurger
     * @param \Magento\Framework\App\Cache\TypeListInterface $cacheTypeList
     */
    public function __construct(
        \Mgt\Varnish\Model\Cache\Config $config,
        \Magento\Framework\App\DeploymentConfig\Writer $deploymentConfigWriter,
        \Magento\Framework\App\Config\ValueFactory $configValueFactory,
        \Magento\CacheInvalidate\Model\PurgeCache $cachePurger,
        \Magento\Framework\App\Cache\TypeListInterface $cacheTypeList
    ) {
        $this->config = $config;
        $this->deploymentConfigWriter = $deploymentConfigWriter;
        $this->configValueFactory = $configValueFactory;
        $this->cachePurger = $cachePurger;
        $this->cacheTypeList = $cacheTypeList;
    }

    /**
     *
     * @param \Magento\Framework\Event\Observer $observer
     */
    public function execute(Observer $observer)
    {
        $isVarnishEnabled = $this->config->isEnabled();

        try {
            $configValue = $this->configValueFactory->create();
            $configValue->load(\Magento\PageCache\Model\Config::XML_PAGECACHE_TYPE, 'path');
            $cacheTypes = $this->cacheTypeList->getTypes();

            if (true === $isVarnishEnabled) {
                $configValue->setPath(\Magento\PageCache\Model\Config::XML_PAGECACHE_TYPE);
                $configValue->setValue(\Magento\PageCache\Model\Config::VARNISH);
                $configValue->save();
                if (isset($cacheTypes['full_page'])) {
                    $cacheTypes['full_page']->setStatus(self::FULL_PAGE_CACHE_STATUS_ENABLED);
                }
            } else {
                if ($configValue->getId()) {
                    $configValue->delete();
                }
                if (isset($cacheTypes['full_page'])) {
                    $cacheTypes['full_page']->setStatus(self::FULL_PAGE_CACHE_STATUS_DISABLED);
                }
                $this->cachePurger->sendPurgeRequest('*');
            }

            $appEnvDataCacheTypes = [];
            if ($cacheTypes) {
                foreach ($cacheTypes as $cacheTypeKey => $cacheType) {
                    $appEnvDataCacheTypes['app_env']['cache_types'][$cacheTypeKey] = (int)$cacheType->getStatus();
                }
            }

            $this->deploymentConfigWriter->saveConfig($appEnvDataCacheTypes, true);
        } catch (\Exception $e) {
            throw new $e;
        }
    }
}
