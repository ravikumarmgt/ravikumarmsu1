<?php
/**
 * Copyright © 2017 MGT-Commerce GmbH. All rights reserved.
 *
 * @category    Mgt
 * @package     Mgt_Varnish
 * @copyright   Copyright (c) 2017 (https://www.mgt-commerce.com)
 */

namespace Mgt\Varnish\Model\Plugin;

use Zend\Uri\Uri;

class PurgeCachePlugin extends \Magento\CacheInvalidate\Model\PurgeCache
{
    const REQUEST_TIMEOUT = 5;

    /**
     * @var \Psr\Log\LoggerInterface
     */
    protected $coreLogger;

    /**
     * @var \Mgt\Varnish\Model\Logger\Logger
     */
    protected $logger;

    /**
     * @var \Mgt\Varnish\Model\Cache\Config
     */
    protected $varnishConfig;

    /**
     * @var \Mgt\Varnish\Model\ResourceModel\Url\Collection
     */
    protected $urlCollection;

    /**
     * @var \Magento\Framework\ObjectManagerInterface
     */
    protected $objectManager;

    /**
     * @var []
     */
    static protected $tagsRegistry = [];

    /**
     * Constructor
     *
     * @param \Magento\PageCache\Model\Cache\Server $cacheServer
     * @param \Magento\CacheInvalidate\Model\SocketFactory $socketAdapterFactory
     * @param \Mgt\Varnish\Model\Cache\Config $varnishConfig
     * @param \Mgt\Varnish\Model\ResourceModel\Url\Collection $urlCollection
     * @param \Magento\Framework\ObjectManagerInterface $objectManager
     * @param \Mgt\Varnish\Model\Logger\Logger $logger
     * @param \Psr\Log\LoggerInterface $coreLogger,
     */
    public function __construct(
        \Magento\PageCache\Model\Cache\Server $cacheServer,
        \Magento\CacheInvalidate\Model\SocketFactory $socketAdapterFactory,
        \Mgt\Varnish\Model\Cache\Config $varnishConfig,
        \Mgt\Varnish\Model\ResourceModel\Url\Collection $urlCollection,
        \Magento\Framework\ObjectManagerInterface $objectManager,
        \Psr\Log\LoggerInterface $coreLogger,
        \Mgt\Varnish\Model\Logger\Logger $logger
    ) {
        $this->cacheServer = $cacheServer;
        $this->socketAdapterFactory = $socketAdapterFactory;
        $this->varnishConfig = $varnishConfig;
        $this->objectManager = $objectManager;
        $this->urlCollection = $urlCollection;
        $this->coreLogger = $coreLogger;
        $this->logger = $logger;
    }

    /**
     * Send curl purge request
     * to invalidate cache by tags pattern
     *
     * @return bool Return true if successful; otherwise return false
     */
    public function sendPurgeRequest($tagsPattern)
    {
        $tags = [];
        if (true === is_array($tagsPattern)) {
            foreach ($tagsPattern as $tag) {
                if (!isset(self::$tagsRegistry[$tag])) {
                    $tags[] = $tag;
                    self::$tagsRegistry[$tag] = $tag;
                }
            }
            if (!$tags) {
                return true;
            }
            $pattern = "((^|,)%s(,|$))";
            $tagsPattern = [];
            foreach ($tags as $tag) {
                $tagsPattern[] = sprintf($pattern, $tag);
            }
            $logMessage = sprintf('Varnish Cache purged by following tags: %s', print_r($tags, true));
            $tagsPattern = implode('|', array_unique($tagsPattern));
        } else {
            $logMessage = '';
            switch ($tagsPattern) {
                case '.*':
                    $logMessage = 'The whole Varnish Cache has been purged';
                break;
            }
        }
        $headers = [self::HEADER_X_MAGENTO_TAGS_PATTERN => $tagsPattern];
        $this->_sendPurgeRequest($headers);

        $isCacheWarmerEnabled = $this->varnishConfig->isCacheWarmerEnabled();
        if (true === $isCacheWarmerEnabled) {
            $this->addToQueue($tags);
        }

        $this->logMessage($logMessage);
        return true;
    }

    public function addToQueue(array $tags)
    {
        if (count($tags)) {
            try {
                $urls = [];
                $this->urlCollection->addTagsFilter($tags);
                foreach ($this->urlCollection as $url) {
                    $urls[] = [
                        'store_id' => $url->getStoreId(),
                        'path'     => $url->getPath(),
                        'priority' => \Mgt\Varnish\Model\UrlQueue::PRIORITY_HIGH
                    ];
                }
                if (count($urls)) {
                    $urlQueue = $this->objectManager->create('Mgt\Varnish\Model\UrlQueue');
                    $urlQueue->addToQueue($urls);
                }
            } catch (\Exception $e) {
                $errorMessage = sprintf('An error occurred during adding to queue, error message: %s', $e->getMessage());
                $this->coreLogger->error($errorMessage);
            }
        }
    }

    public function purgeStoreRequest(\Magento\Store\Model\Store $store)
    {
        $uri = new Uri($store->getBaseUrl());
        $headers = ['HOST' => $uri->getHost()];
        $this->_sendPurgeRequest($headers);
        $logMessage = sprintf('Store with base url: %s (ID: %s) has been purged', $store->getBaseUrl(), $store->getStoreId());
        $this->logMessage($logMessage);
    }

    public function purgeUrlRequest($url)
    {
        $uri = new Uri($url);
        $headers = [
            'HOST' => $uri->getHost(),
        ];
        $this->_sendPurgeRequest($headers, $uri->getPath());
        $logMessage = sprintf('Url: %s has been purged', $url);
        $this->logMessage($logMessage);
    }

    protected function _sendPurgeRequest(array $headers, $path = null)
    {
        $socketAdapter = $this->socketAdapterFactory->create();
        $socketAdapter->setOptions(['timeout' => self::REQUEST_TIMEOUT]);
        $servers = $this->getCacheServers();
        foreach ($servers as $server) {
            try {
                if (null !== $path) {
                    $server->setPath($path);
                }
                $socketAdapter->connect($server->getHost(), $server->getPort());
                $socketAdapter->write(
                    'PURGE',
                    $server,
                    '1.1',
                    $headers
                );
                $socketAdapter->close();
            } catch (\Exception $e) {
                $errorMessage = sprintf('An error occurred during purging, error message: "%s"', $e->getMessage());
                $this->logMessage($errorMessage, true);
                throw new \Exception($errorMessage);
            }
        }
    }

    protected function logMessage($message, $force = false)
    {
        $isDebugModeEnabled = $this->varnishConfig->isDebugModeEnabled();
        if (true === $isDebugModeEnabled || true === $force) {
            $this->logger->debug($message);
        }
    }

    protected function getCacheServers()
    {
        $cacheServers = [];
        $serverList = $this->varnishConfig->getServerList();
        foreach ($serverList as $server) {
            list($host, $port) = explode(':', $server);
            $uri = new Uri();
            $uri->setHost($host);
            $uri->setPort($port);
            $uri->setPath('/');
            $uri->setScheme('http');
            $uri->setQuery(null);
            $cacheServers[] = $uri;
        }
        return $cacheServers;
    }
}