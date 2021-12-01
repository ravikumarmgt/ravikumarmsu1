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

class ProductSaveAfterObserver implements ObserverInterface
{
    /**
     * @var \Magento\PageCache\Model\Config
     */
    protected $config;

    /**
     * @var \Magento\CatalogUrlRewrite\Model\ProductUrlRewriteGenerator
     */
    protected $productUrlRewriteGenerator;

    /**
     * @var \Magento\ConfigurableProduct\Model\ResourceModel\Product\Type\Configurable
     */
    protected $catalogProductTypeConfigurable;

    /**
     * @var \Magento\Catalog\Model\ProductFactory
     */
    protected $productFactory;

    /**
     * @var \Mgt\Varnish\Model\Cache\Config
     */
    protected $varnishConfig;

    /**
     * @var \Mgt\Varnish\Model\UrlQueue
     */
    protected $urlQueue;

    /**
     * @var bool
     */
    static protected $isQueued = false;

    /**
     * @param \Magento\PageCache\Model\Config $config
     * @param \Magento\CatalogUrlRewrite\Model\ProductUrlRewriteGenerator $productUrlRewriteGenerator
     * @param \Magento\ConfigurableProduct\Model\ResourceModel\Product\Type\Configurable $catalogProductTypeConfigurable
     * @param \Magento\Catalog\Model\ProductFactory $productFactory
     * @param \Mgt\Varnish\Model\UrlQueue $urlQueue
     * @param \Mgt\Varnish\Model\Cache\Config $varnishConfig
     */
    public function __construct(
        \Magento\PageCache\Model\Config $config,
        \Magento\CatalogUrlRewrite\Model\ProductUrlRewriteGenerator $productUrlRewriteGenerator,
        \Magento\ConfigurableProduct\Model\ResourceModel\Product\Type\Configurable $catalogProductTypeConfigurable,
        \Magento\Catalog\Model\ProductFactory $productFactory,
        \Mgt\Varnish\Model\UrlQueue $urlQueue,
        \Mgt\Varnish\Model\Cache\Config $varnishConfig
    ) {
        $this->config = $config;
        $this->productUrlRewriteGenerator = $productUrlRewriteGenerator;
        $this->catalogProductTypeConfigurable = $catalogProductTypeConfigurable;
        $this->productFactory = $productFactory;
        $this->urlQueue = $urlQueue;
        $this->varnishConfig = $varnishConfig;
    }

    /**
     * @param \Magento\Framework\Event\Observer $observer
     * @return void
     */
    public function execute(\Magento\Framework\Event\Observer $observer)
    {
        $product = $observer->getEvent()->getProduct();
        $isCacheWarmerEnabled = $this->varnishConfig->isCacheWarmerEnabled();
        if (true === $isCacheWarmerEnabled && isset($product) && $product instanceof \Magento\Catalog\Model\Product) {
            $productUrls = $this->productUrlRewriteGenerator->generate($product);
            $urls = [];
            if (false === empty($productUrls)) {
                foreach ($productUrls as $url) {
                    $urls[] = [
                        'store_id' => $url->getStoreId(),
                        'path'     => $url->getRequestPath(),
                        'priority' => \Mgt\Varnish\Model\UrlQueue::PRIORITY_HIGH
                    ];
                }
            } else {
                $productId = $product->getId();
                $parentProductIds = $this->catalogProductTypeConfigurable->getParentIdsByChild($productId);
                if (count($parentProductIds)) {
                    foreach ($parentProductIds as $parentProductId) {
                        $product = $this->productFactory->create();
                        $product->load($parentProductId);
                        $productUrls = $this->productUrlRewriteGenerator->generate($product);
                        foreach ($productUrls as $url) {
                            $urls[] = [
                                'store_id' => $url->getStoreId(),
                                'path'     => $url->getRequestPath(),
                                'priority' => \Mgt\Varnish\Model\UrlQueue::PRIORITY_HIGH
                            ];
                        }
                    }
                }
            }
           if (count($urls)) {
              try {
                  $this->urlQueue->addToQueue($urls);
              } catch (\Exception $e) {
              }
           }
        }
    }
}
