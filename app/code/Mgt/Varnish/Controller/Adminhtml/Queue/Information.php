<?php
/**
 * Copyright © 2017 MGT-Commerce GmbH. All rights reserved.
 *
 * @category    Mgt
 * @package     Mgt_Varnish
 * @copyright   Copyright (c) 2017 (https://www.mgt-commerce.com)
 */

namespace Mgt\Varnish\Controller\Adminhtml\Queue;

class Information extends \Magento\Backend\App\Action
{
    const SQL_LIMIT_URL_QUEUE = 500;

    /**
     * @var \Magento\Framework\Json\Helper\Data
     */
    protected $jsonHelper;

    /**
     * @var \Magento\Store\Model\StoreManagerInterface
     */
    protected $storeManager;

    /**
     * @var \Mgt\Varnish\Model\ResourceModel\UrlQueue\Collection
     */
    protected $urlQueueCollection;

    /**
     * Initialize ListAction
     *
     * @param \Magento\Backend\App\Action\Context $context
     * @param \Magento\Framework\Json\Helper\Data $jsonHelper
     * @param \Mgt\Varnish\Model\ResourceModel\UrlQueue\Collection $urlQueueCollection
     */
    public function __construct(
        \Magento\Backend\App\Action\Context $context,
        \Magento\Framework\Json\Helper\Data $jsonHelper,
        \Magento\Store\Model\StoreManagerInterface $storeManager,
        \Mgt\Varnish\Model\ResourceModel\UrlQueue\Collection $urlQueueCollection
    ) {
        parent::__construct($context);
        $this->jsonHelper = $jsonHelper;
        $this->urlQueueCollection = $urlQueueCollection;
        $this->storeManager = $storeManager;
    }

    public function execute()
    {
        $numberOfUrls = $this->urlQueueCollection->getSize();
        $urlsInQueue = $this->getUrlsFromQueue();
        $data = ['numberOfUrls' => $numberOfUrls, 'content' => implode('<br>', $urlsInQueue)];
        $response = $this->getResponse();
        $response->representJson($this->jsonHelper->jsonEncode($data));
        return $response;
    }

    public function getUrlsFromQueue()
    {
        $urls = [];
        $this->urlQueueCollection->addOrder('priority');
        $this->urlQueueCollection->setPageSize(self::SQL_LIMIT_URL_QUEUE);
        $this->urlQueueCollection->load();
        foreach ($this->urlQueueCollection as $url) {
            $storeId = $url->getStoreId();
            $store = $this->storeManager->getStore($storeId);
            $url = sprintf('%s/%s', rtrim($store->getBaseUrl(),'/'), ltrim($url->getPath(), '/'));
            $urls[] = $url;
        }
        return $urls;
    }
}