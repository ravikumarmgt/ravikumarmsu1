<?php
/**
 * Copyright © 2017 MGT-Commerce GmbH. All rights reserved.
 *
 * @category    Mgt
 * @package     Mgt_Varnish
 * @copyright   Copyright (c) 2017 (https://www.mgt-commerce.com)
 */

namespace Mgt\Varnish\Console\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Process\Process;

class CacheWarmerCommand extends Command
{
    /**
     * Crawler user agent name
     */
    const USER_AGENT = 'MgtVarnishCrawler';

    /**
     * Cache Warmer Cache Key
     */
    const CACHE_WARMER_CACHE_KEY = 'MgtCacheWarmer';

    /**
     * Cache Warmer Crawled Urls
     */
    const CACHE_WARMER_CRAWLED_URLS = 'MgtCacheWarmerCrawledUrls';

    /**
     * @var \Magento\Framework\HTTP\Adapter\Curl
     */
    protected $curlAdapter;

    /**
     * @var \Psr\Log\LoggerInterface
     */
    protected $logger;

    /**
     * @var \Magento\Framework\App\Filesystem\DirectoryList
     */
    protected $directoryList;

    /**
     * @var \Magento\Store\Model\StoreManagerInterface
     */
    protected $storeManager;

    /**
     * @var \Mgt\Varnish\Model\Cache\Backend\File
     */
    protected $cache;

    /**
     * @var \Magento\CacheInvalidate\Model\PurgeCache
     */
    protected $cachePurger;

    /**
     * @var string lock file
     */
    protected $lockFile;

    /**
     * @var boolean
     */
    protected $isLocked;

    /**
     * @var \Mgt\Varnish\Model\Cache\Config
     */
    protected $varnishConfig;

    /**
     * @var \Mgt\Varnish\Model\ResourceModel\Url
     */
    protected $urlResource;

    /**
     * @var \Mgt\Varnish\Model\ResourceModel\UrlQueue
     */
    protected $urlQueueResource;

    /**
     * @var \Mgt\Varnish\Model\ResourceModel\UrlQueue\Collection
     */
    protected $urlQueueCollection;

    /**
     * Constructor
     *
     * @param \Magento\Framework\HTTP\Adapter\Curl $curlAdapter
     * @param \Psr\Log\LoggerInterface $logger,
     * @param \Magento\Framework\App\Filesystem\DirectoryList $directoryList
     * @param \Magento\Store\Model\StoreManagerInterface $storeManager
     * @param \Mgt\Varnish\Model\Cache\Backend\File $cache
     * @param \Magento\Framework\App\CacheInterface $cacheManager
     * @param \Mgt\Varnish\Model\Cache\Config $varnishConfig
     * @param \Mgt\Varnish\Model\ResourceModel\Url $urlResource
     * @param \Mgt\Varnish\Model\ResourceModel\UrlQueue $urlQueueResource
     */
    public function __construct(
        \Magento\Framework\HTTP\Adapter\Curl $curlAdapter,
        \Psr\Log\LoggerInterface $logger,
        \Magento\Framework\App\Filesystem\DirectoryList $directoryList,
        \Magento\Store\Model\StoreManagerInterface $storeManager,
        \Mgt\Varnish\Model\Cache\Backend\File $cache,
        \Magento\CacheInvalidate\Model\PurgeCache $cachePurger,
        \Mgt\Varnish\Model\Cache\Config $varnishConfig,
        \Mgt\Varnish\Model\ResourceModel\Url $urlResource,
        \Mgt\Varnish\Model\ResourceModel\UrlQueue $urlQueueResource,
        \Mgt\Varnish\Model\ResourceModel\UrlQueue\Collection $urlQueueCollection

    ) {
        $this->curlAdapter = $curlAdapter;
        $this->logger = $logger;
        $this->directoryList = $directoryList;
        $this->storeManager = $storeManager;
        $this->cache = $cache;
        $this->cachePurger = $cachePurger;
        $this->varnishConfig = $varnishConfig;
        $this->urlResource = $urlResource;
        $this->urlQueueResource = $urlQueueResource;
        $this->urlQueueCollection = $urlQueueCollection;
        parent::__construct();
    }

    /**
     * {@inheritdoc}
     */
    protected function configure()
    {
        $this->setName('mgt-varnish:cache-warmer');
        $this->setDescription('MGT Varnish Cache Warmer');
        parent::configure();
    }

    /**
     * {@inheritdoc}
     */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        try {
            ini_set('memory_limit','2048M');
            if (false === $this->isLocked()) {
                $this->lock();
                $this->deleteExpiredUrls();
                $break = false;
                $i = 0;
                do {
                    $this->updateTimestamp();
                    $isCacheWarmerCpuLimitEnabled = $this->varnishConfig->isCacheWarmerCpuLimitEnabled();
                    if (true === $isCacheWarmerCpuLimitEnabled) {
                        $numberOfProcessingUnits = $this->runCommand('nproc');
                        $loadAverage = sys_getloadavg();
                        $totalCpuUtilization = $loadAverage[0] * 100 / $numberOfProcessingUnits;
                        $totalCpuUtilization = min($totalCpuUtilization, 100);
                        $cacheWarmerCpuLimit = $this->varnishConfig->getCacheWarmerCpuLimit();
                        if ($totalCpuUtilization > $cacheWarmerCpuLimit) {
                            $break = true;
                            $output->writeln(sprintf('Currently the CPU limit has been reached, CPU: "%s percent", Limit: "%s percent"', round($totalCpuUtilization), round($cacheWarmerCpuLimit)));
                        }
                    }
                    if (false === $break) {
                        $numberOfThreads = $this->varnishConfig->getNumberOfCacheWarmerThreads();
                        $i = $i + $numberOfThreads;
                        $this->urlQueueCollection->clear();
                        $this->urlQueueCollection->setPageSize($numberOfThreads);
                        $this->urlQueueCollection->addOrder('priority');
                        $this->urlQueueCollection->load();
                        if (count($this->urlQueueCollection)) {
                            $urls = [];
                            foreach ($this->urlQueueCollection as $urlQueue) {
                                try {
                                    $storeId = $urlQueue->getStoreId();
                                    $store = $this->storeManager->getStore($storeId);
                                    $url = sprintf('%s/%s', rtrim($store->getBaseUrl(),'/'), ltrim($urlQueue->getPath(), '/'));
                                    $urls[$urlQueue->getId()] = $url;
                                } catch (\Exception $e) {
                                }
                            }
                            $this->crawlUrls($urls, $output);
                            $this->deleteFromQueue($urls);
                        } else {
                            $break = true;
                        }
                    }
                    if ($i == 1000) {
                        $break = true;
                    }
                } while ($break == false);

            } else {
                $output->writeln('Cache Warmer is already running');
            }
        } catch (\Exception $e) {
            $errorMessage = $e->getMessage();
            $output->writeln(sprintf('<error>%s</error>', $errorMessage));
            return \Magento\Framework\Console\Cli::RETURN_FAILURE;
        }
    }

    protected function updateTimestamp()
    {
        $now = new \DateTime('now', new \DateTimeZone('UTC'));
        $now = $now->getTimestamp();
        $this->cache->save($now, self::CACHE_WARMER_CACHE_KEY);
    }

    public function crawlUrls(array $urls, OutputInterface $output)
    {
        try {
            $options = array(
                CURLOPT_USERAGENT      => self::USER_AGENT,
                CURLOPT_SSL_VERIFYPEER => 0,
            );
            $this->curlAdapter->multiRequest($urls, $options);
            foreach ($urls as $url) {
                $output->writeln(sprintf('<info>"%s" crawled</info>', $url));
            }
        } catch (\Exception $e) {
            $errorMessage = sprintf('An error occurred during crawling urls, error message: %s', $e->getMessage());
            $this->logger->error($errorMessage);
        }
    }

    protected function deleteExpiredUrls()
    {
        try {
            $this->urlResource->deleteExpiredUrls();
        } catch (\Exception $e) {
            $errorMessage = sprintf('An error occurred during deleting expired urls, error message: %s', $e->getMessage());
            $this->logger->error($errorMessage);
        }
    }

    public function deleteFromQueue(array $urls)
    {
        try {
            $urlIds = array_keys($urls);
            $this->urlQueueResource->deleteFromQueue($urlIds);
        } catch (\Exception $e) {
            $errorMessage = sprintf('An error occurred during deleting urls, error message: %s', $e->getMessage());
            $this->logger->error($errorMessage);
        }
    }

    protected function getLockFile()
    {
        if (null === $this->lockFile) {
            $lockFileDirectory = $this->directoryList->getPath('tmp');
            $lockFile = sprintf('%s/mgt_varnish_cache_crawler.lock', $lockFileDirectory);
            $filesystem = new Filesystem();
            $filesystem->mkdir(dirname($lockFile));
            if (is_file($lockFile)) {
                $this->lockFile = fopen($lockFile, 'w');
            } else {
                $this->lockFile = fopen($lockFile, 'x');
            }
            fwrite($this->lockFile, date('r'));
        }
        return $this->lockFile;
    }

    protected function lock()
    {
        $this->isLocked = true;
        $lockFile = $this->getLockFile();
        flock($lockFile, LOCK_EX | LOCK_NB);
        return $this;
    }

    protected function unlock()
    {
        $this->isLocked = false;
        $lockFile = $this->getLockFile();
        flock($lockFile, LOCK_UN);
        return $this;
    }

    protected function isLocked()
    {
        if ($this->isLocked !== null) {
            return $this->isLocked;
        } else {
            $fp = $this->getLockFile();
            if (flock($fp, LOCK_EX | LOCK_NB)) {
                flock($fp, LOCK_UN);
                return false;
            }
            return true;
        }
    }

    protected function runCommand($command, $timeout = 30)
    {
        $process = new Process($command);
        $process->setTimeout($timeout);
        $process->run();

        if (false === $process->isSuccessful()) {
            throw new \RuntimeException($process->getErrorOutput());
        }

        $output = trim($process->getOutput());
        return $output;
    }

    public function __destruct()
    {
        $this->unlock();
    }
}