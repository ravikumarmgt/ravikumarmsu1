<?php
/**
 * Copyright © 2017 MGT-Commerce GmbH. All rights reserved.
 *
 * @category    Mgt
 * @package     Mgt_Varnish
 * @copyright   Copyright (c) 2017 (https://www.mgt-commerce.com)
 */

namespace Mgt\Varnish\Model\Cache;

class Config
{
    /**
     * @var \Magento\Framework\App\Config
     */
    protected $config;

    /**
     * @var \Magento\Framework\App\DeploymentConfig\Writer
     */
    protected $deploymentConfigWriter;

    /**
     * @var \Magento\Framework\App\DeploymentConfig\Reader
     */
    protected $deploymentConfigReader;

    /**
     * @var \Magento\Config\Model\Config\Factory
     */
    protected $configFactory;

    /**
     * @var \Magento\Store\Model\StoreManagerInterface
     */
    protected $storeManager;

    /**
     * @param \Magento\Framework\App\DeploymentConfig\Writer $deploymentConfigWriter
     * @param \Magento\Framework\App\DeploymentConfig\Reader $deploymentConfigReader
     * @param \Magento\Framework\App\Config $config
     * @param \Magento\Config\Model\Config\Factory $configFactory
     */
    public function __construct(
        \Magento\Framework\App\DeploymentConfig\Writer $deploymentConfigWriter,
        \Magento\Framework\App\DeploymentConfig\Reader $deploymentConfigReader,
        \Magento\Framework\App\Config $config,
        \Magento\Config\Model\Config\Factory $configFactory,
        \Magento\Store\Model\StoreManagerInterface $storeManager
    ) {
        $this->deploymentConfigWriter = $deploymentConfigWriter;
        $this->deploymentConfigReader = $deploymentConfigReader;
        $this->config = $config;
        $this->configFactory = $configFactory;
        $this->storeManager = $storeManager;
    }
    
    public function isEnabled($store = null)
    {
        $isEnabled = (bool)$this->getConfigValue('mgt_varnish/module/is_enabled', $store);
        return $isEnabled;
    }

    public function getServerList($store = null)
    {
        $serverList = array_map('trim', explode(',', $this->getConfigValue('mgt_varnish/module/server_list', $store)));
        return $serverList;
    }

    public function getExcludedRoutes($store = null)
    {
        $excludedRoutes = explode("\n", trim($this->getConfigValue('mgt_varnish/module/excluded_routes', $store)));
        return $excludedRoutes;
    }

    public function getExcludedUrls($store = null)
    {
        $excludedUrls = explode("\n", trim($this->getConfigValue('mgt_varnish/module/excluded_urls', $store)));
        return $excludedUrls;
    }

    public function getExcludedParams($store = null)
    {
        $excludedParams = array_map('trim', explode(',', $this->getConfigValue('mgt_varnish/module/excluded_params', $store)));
        return $excludedParams;
    }

    public function getDefaultCacheLifetime($store = null)
    {
        $defaultCacheLifetime = (int)$this->getConfigValue('mgt_varnish/module/default_cache_lifetime', $store);
        return $defaultCacheLifetime;
    }

    public function isDebugModeEnabled($store = null)
    {
      $isDebugModeEnabled = (bool)$this->getConfigValue('mgt_varnish/module/debug_mode', $store);
      return $isDebugModeEnabled;
    }

    public function getApiSecretKey($store = null)
    {
        $apiSecretKey = trim($this->getConfigValue('mgt_varnish/module/api_secret_key', $store));
        return $apiSecretKey;
    }

    public function getRoutesCacheLifetime($store = null)
    {
      $routesCacheLifetime = trim($this->getConfigValue('mgt_varnish/module/routes_cache_lifetime', $store));
      $routesCacheLifetime = json_decode($routesCacheLifetime, true);
      $routesCacheLifetime = (array)$routesCacheLifetime;
      return $routesCacheLifetime;
    }

    public function isCacheWarmerEnabled($store = null)
    {
        $isCacheWarmerEnabled = (bool)$this->getConfigValue('mgt_varnish/module/cache_warmer_enabled', $store);
        return $isCacheWarmerEnabled;
    }

    public function getCacheWarmerRoutes($store = null)
    {
        $cacheWarmerRoutes = array_map('trim', explode("\n", trim($this->getConfigValue('mgt_varnish/module/cache_warmer_routes', $store))));
        return $cacheWarmerRoutes;
    }

    public function getNumberOfCacheWarmerThreads($store = null)
    {
        $numberOfCacheWarmerThreads = (int)$this->getConfigValue('mgt_varnish/module/cache_warmer_threads', $store);
        return $numberOfCacheWarmerThreads;
    }

    public function getCacheWarmerCpuLimit($store = null)
    {
        $cacheWarmerCpuLimit = (int)$this->getConfigValue('mgt_varnish/module/cache_warmer_cpu_limit', $store);
        return $cacheWarmerCpuLimit;
    }

    public function isCacheWarmerCpuLimitEnabled($store = null)
    {
        $isCacheWarmerCpuLimitEnabled = (bool)$this->getConfigValue('mgt_varnish/module/cache_warmer_cpu_limit_enabled', $store);
        return $isCacheWarmerCpuLimitEnabled;
    }

    protected function getConfigValue($path, $store = null, $scope = \Magento\Store\Model\ScopeInterface::SCOPE_STORE)
    {
        if (null === $store) {
            $store = $this->storeManager->getStore();
        }
        $configValue = $this->config->getValue($path, $scope, $store);
        return $configValue;
    }
}