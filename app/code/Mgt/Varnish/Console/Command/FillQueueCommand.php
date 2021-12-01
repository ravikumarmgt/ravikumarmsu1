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
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputDefinition;
use Symfony\Component\Console\Output\OutputInterface;

class FillQueueCommand extends Command
{
    /**
     * Input store id option name
     */
    const INPUT_STORE_ID = 'store-id';

    /**
     * Entity Type Category
     */
    const ENTITY_TYPE_CATEGORY = 'category';

    /**
     * Entity Type Product
     */
    const ENTITY_TYPE_PRODUCT = 'product';

    /**
     * Url Queue batch size
     */
    const URL_QUEUE_BATCH_SIZE = 2500;

    /**
     * @var \Psr\Log\LoggerInterface
     */
    protected $logger;

    /**
     * @var \Magento\Store\Model\StoreManagerInterface
     */
    protected $storeManager;

    /**
     * @var \Magento\Catalog\Model\ResourceModel\Category\Collection
     */
    protected $categoryCollection;

    /**
     * @var \Mgt\Varnish\Model\ResourceModel\UrlQueue
     */
    protected $urlQueueResource;

    /**
     * @var \Mgt\Varnish\Model\UrlQueue
     */
    protected $urlQueue;

    /**
     * @var int
     */
    protected $numberOfUrls = 0;

    /**
     * @var []
     */
    protected $categories = [];

    protected $state;

    public function __construct()
    {
        $objectManager = $this->getObjectManager();
        $this->logger = $objectManager->get('\Psr\Log\LoggerInterface');
        $this->storeManager = $objectManager->get('\Magento\Store\Model\StoreManagerInterface');
        $this->categoryCollection = $objectManager->get('\Magento\Catalog\Model\ResourceModel\Category\Collection');
        $this->urlQueueResource = $objectManager->get('\Mgt\Varnish\Model\ResourceModel\UrlQueue');
        $this->urlQueue = $objectManager->get('\Mgt\Varnish\Model\UrlQueue');
        //$this->state = $objectManager->get('\Magento\Framework\App\State');
        parent::__construct();
    }

    /**
     * {@inheritdoc}
     */
    protected function configure()
    {
        $this->setName('mgt-varnish:fill-queue');
        $this->setDescription('MGT Varnish Cache Queue Filler');
        $this->setDefinition(
            new InputDefinition(array(
                new InputOption(self::INPUT_STORE_ID, null, InputOption::VALUE_OPTIONAL, ''),
            ))
        );
        parent::configure();
    }

    /**
     * {@inheritdoc}
     */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        try {
            ini_set('memory_limit','2048M');
            $store = null;
            $storeId = (int)$input->getOption(self::INPUT_STORE_ID);
            //$this->state->setAreaCode(\Magento\Framework\App\Area::AREA_FRONTEND);
            if ($storeId) {
                try {
                    $store = $this->storeManager->getStore($storeId);
                    $this->storeManager->setCurrentStore($store);
                } catch (\Exception $e) {
                    $output->writeln(sprintf('<error>Store with ID "%s" does not exists</error>', $storeId));
                    $output->writeln('');
                    $output->writeln(sprintf('<comment>Available Stores</comment>'));
                    return $this->showStores($output);
                }
            }
            $this->addCategoryUrls($store);
            $this->addProductUrls($store);
            if ($this->numberOfUrls > 0) {
                $output->writeln(sprintf('<info>%s URLs added to Varnish Queue</info>', $this->numberOfUrls));
            }
        } catch (\Exception $e) {
            $errorMessage = $e->getMessage();
            $output->writeln(sprintf('<error>%s</error>', $errorMessage));
            return \Magento\Framework\Console\Cli::RETURN_FAILURE;
        }
    }

    protected function addCategoryUrls(\Magento\Store\Model\Store $store = null)
    {
        $objectManager = $this->getObjectManager();
        $urlRewriteCollection = $objectManager->create('\Mgt\Varnish\Model\ResourceModel\UrlRewrite\UrlRewriteCollection');
        if (null !== $store) {
            $storeId = $store->getStoreId();
            $this->categoryCollection->setStore($store);
            $urlRewriteCollection->addStoreFilter($storeId, false);
        }
        $this->categoryCollection->addAttributeToSelect('entity_id');
        foreach ($this->categoryCollection as $category) {
            $this->categories[$category->getId()] = $category;
        }
        if (count($this->categories)) {
            $categoryIds = array_keys($this->categories);
            $urlRewriteCollection->addEntityTypeFilter(self::ENTITY_TYPE_CATEGORY);
            $urlRewriteCollection->addEntityIdFilter($categoryIds);
            $urlRewrites = [];
            $urls = [];
            foreach ($urlRewriteCollection as $urlRewrite) {
                $urlRewriteId = $urlRewrite->getUrlRewriteId();
                if (!isset($urlRewrites[$urlRewriteId])) {
                    $urls[] = [
                        'store_id' => $urlRewrite->getStoreId(),
                        'path'     => $urlRewrite->getRequestPath(),
                        'priority' => \Mgt\Varnish\Model\UrlQueue::PRIORITY_MEDIUM
                    ];
                    $urlRewrites[$urlRewriteId] = $urlRewriteId;
                }
            }
            if (count($urls)) {
                $this->numberOfUrls += count($urls);
                $this->urlQueue->addToQueue($urls);
            }
        }
    }

    protected function addProductUrls(\Magento\Store\Model\Store $store = null)
    {
        if (count($this->categories)) {
            $objectManager = $this->getObjectManager();
            $configurableProduct = $objectManager->get('\Magento\ConfigurableProduct\Model\ResourceModel\Product\Type\Configurable');
            $productStatus = $objectManager->get('\Magento\Catalog\Model\Product\Attribute\Source\Status');
            $productVisibility = $objectManager->get('\Magento\Catalog\Model\Product\Visibility');
            $productIds = [];
            foreach ($this->categories as $category) {
                $productCollection = $objectManager->create('\Magento\Catalog\Model\ResourceModel\Product\Collection');
                $productCollection->addAttributeToSelect(['entity_id', 'status']);
                $productCollection->addAttributeToFilter('status', ['in' => $productStatus->getVisibleStatusIds()]);
                $productCollection->setVisibility($productVisibility->getVisibleInSiteIds());
                $productCollection->addCategoryFilter($category);
                $break = false;
                $i = 0;
                do {
                    $productCollection->clear();
                    if (null !== $store) {
                        $productCollection->addStoreFilter($store);
                    }
                    $productCollection->setCurPage(++$i);
                    $productCollection->setPageSize(self::URL_QUEUE_BATCH_SIZE);
                    $entityIds = [];
                    foreach ($productCollection as $product) {
                        $productId = $product->getId();
                        if (!isset($productIds[$productId])) {
                            if ('configurable' == $product->getTypeId()) {
                                $productIds[$productId] = $productId;
                                $entityIds[$productId] = $productId;
                            } else {
                                $parentIds = $configurableProduct->getParentIdsByChild($productId);
                                if (true === empty($parentIds)) {
                                    $productIds[$productId] = $productId;
                                    $entityIds[$productId] = $productId;
                                }
                            }
                        }
                    }
                    if (false === empty($entityIds)) {
                        $urlRewriteCollection = $objectManager->create('\Mgt\Varnish\Model\ResourceModel\UrlRewrite\UrlRewriteCollection');
                        if (null !== $store) {
                            $storeId = $store->getStoreId();
                            $urlRewriteCollection->addStoreFilter($storeId, false);
                        }
                        $urlRewriteCollection->addEntityTypeFilter(self::ENTITY_TYPE_PRODUCT);
                        $urlRewriteCollection->addEntityIdFilter($entityIds);
                        $urlRewrites = [];
                        $urls = [];
                        foreach ($urlRewriteCollection as $urlRewrite) {
                            $urlRewriteId = $urlRewrite->getUrlRewriteId();
                            if (!isset($urlRewrites[$urlRewriteId])) {
                                $urls[] = [
                                    'store_id' => $urlRewrite->getStoreId(),
                                    'path'     => $urlRewrite->getRequestPath(),
                                    'priority' => \Mgt\Varnish\Model\UrlQueue::PRIORITY_LOW
                                ];
                                $urlRewrites[$urlRewriteId] = $urlRewriteId;
                            }
                        }
                        if (count($urls)) {
                            $this->numberOfUrls += count($urls);
                            $this->urlQueue->addToQueue($urls);
                        }
                    } else {
                        $break = true;
                    }
                } while ($break == false);
            }
        }
    }

    protected function getObjectManager()
    {
        $objectManager = \Magento\Framework\App\ObjectManager::getInstance();
        return $objectManager;
    }

    protected function showStores(OutputInterface $output)
    {
        $table = $this->getHelperSet()->get('table');
        $table->setHeaders(['Store ID', 'Base URL']);
        $stores = $this->storeManager->getStores();
        foreach ($stores as $store) {
            $row = [
                $store->getStoreId(),
                $store->getBaseUrl()
            ];
            $table->addRow($row);
        }
        $table->render($output);
    }
}
