<?php
/**
 * Copyright © 2017 MGT-Commerce GmbH. All rights reserved.
 *
 * @category    Mgt
 * @package     Mgt_Varnish
 * @copyright   Copyright (c) 2017 (https://www.mgt-commerce.com)
 */

namespace Mgt\Varnish\Controller\Adminhtml\Purge;

class Action extends \Magento\Backend\App\Action
{
    public function execute()
    {
        $request = $this->getRequest();
        $storeId = (int)$request->getParam('store_id');
        try {
            $cachePurger = $this->_objectManager->get('\Magento\CacheInvalidate\Model\PurgeCache');
            $storeManager = $this->_objectManager->get('\Magento\Store\Model\StoreManagerInterface');
            $store = $storeManager->getStore($storeId);
            $cachePurger->purgeStoreRequest($store);
            $storeBaseUrl = $store->getBaseUrl();
            $this->messageManager->addSuccessMessage(sprintf('The Store "%s" has been purged from Varnish Cache', $storeBaseUrl));
        } catch (\Exception $e) {
            $errorMessage = $e->getMessage();
            $this->messageManager->addErrorMessage($errorMessage);
        }
        $resultRedirect = $this->resultRedirectFactory->create();
        return $resultRedirect->setPath('adminhtml/cache/index');
    }
}
