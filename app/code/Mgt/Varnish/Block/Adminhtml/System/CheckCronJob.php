<?php
/**
 * Copyright © 2017 MGT-Commerce GmbH. All rights reserved.
 *
 * @category    Mgt
 * @package     Mgt_Varnish
 * @copyright   Copyright (c) 2017 (https://www.mgt-commerce.com)
 */

namespace Mgt\Varnish\Block\Adminhtml\System;

class CheckCronJob extends \Magento\Backend\Block\Template
{
    /**
     * Cache Warmer Cache Key
     */
    const CACHE_WARMER_CACHE_KEY = 'MgtCacheWarmer';

    /**
     * Cron warning message minutes
     */
     const CRON_WARNING_MESSAGE_MINUTES = 10;

    /**
     * @var \Mgt\Varnish\Model\Cache\Backend\File
     */
    protected $cache;

    /**
    * @var \Mgt\Varnish\Model\Cache\Config
    */
    protected $varnishConfig;

    /**
     * @var \Magento\Framework\App\Config
     */
    protected $config;

    /**
     * @var \Magento\Framework\App\Filesystem\DirectoryList
     */
    protected $directoryList;

    /**
     * @param \Magento\Backend\Block\Template\Context $context
     * @param \Magento\Framework\App\Filesystem\DirectoryList $directoryList
     * @param \Mgt\Varnish\Model\Cache\Backend\File $cache
     * @param \Magento\Framework\App\Config $config
     * @param \Mgt\Varnish\Model\Cache\Config $varnishConfig
     * @param array $data
     * @SuppressWarnings(PHPMD.ExcessiveParameterList)
     */
    public function __construct(
        \Magento\Backend\Block\Template\Context $context,
        \Magento\Framework\App\Filesystem\DirectoryList $directoryList,
        \Mgt\Varnish\Model\Cache\Backend\File $cache,
        \Magento\Framework\App\Config $config,
        \Mgt\Varnish\Model\Cache\Config $varnishConfig,
        array $data = []
    ) {
        parent::__construct($context, $data);
        $this->directoryList = $directoryList;
        $this->cache = $cache;
        $this->config = $config;
        $this->varnishConfig = $varnishConfig;
    }

    public function isVarnishEnabled()
    {
        $isVarnishEnabled = $this->varnishConfig->isEnabled();
        return $isVarnishEnabled;
    }

    public function isCacheWarmerEnabled()
    {
        $isCacheWarmerEnabled = $this->varnishConfig->isCacheWarmerEnabled();
        return $isCacheWarmerEnabled;
    }

    public function showCronNotRunningMessage()
    {
        $showCronNotRunningMessage = false;
        $isVarnishEnabled = $this->isVarnishEnabled();
        $isCacheWarmerEnabled = $this->isCacheWarmerEnabled();
        if (true === $isVarnishEnabled && true === $isCacheWarmerEnabled) {
            $lastRunningTimestamp = $this->getLastRunningTimestamp();
            if (0 == $lastRunningTimestamp) {
                $showCronNotRunningMessage = true;
            } else {
                $now = new \DateTime('now', new \DateTimeZone('UTC'));
                $lastRunning = new \Datetime();
                $lastRunning->setTimezone(new \DateTimeZone('UTC'));
                $lastRunning->setTimestamp($lastRunningTimestamp);
                $dateDiff = $now->diff($lastRunning);
                $totalMinutes = $dateDiff->days * 24 * 60;
                $totalMinutes += $dateDiff->h * 60;
                $totalMinutes += $dateDiff->i;
                if ($totalMinutes >= self::CRON_WARNING_MESSAGE_MINUTES) {
                    $showCronNotRunningMessage = true;
                }
            }
        }
        return $showCronNotRunningMessage;
    }

    protected function getLastRunningTimestamp()
    {
        $lastRunningTimestamp = (int)$this->cache->load(self::CACHE_WARMER_CACHE_KEY);
        return $lastRunningTimestamp;
    }

    public function getCronJobCommand()
    {
        $cronJobCommand = sprintf('php %s/bin/magento mgt-varnish:cache-warmer', $this->directoryList->getRoot());
        return $cronJobCommand;
    }
}
