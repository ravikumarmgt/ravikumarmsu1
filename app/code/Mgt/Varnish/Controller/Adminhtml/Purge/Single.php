<?php
/**
 * Copyright © 2017 MGT-Commerce GmbH. All rights reserved.
 *
 * @category    Mgt
 * @package     Mgt_Varnish
 * @copyright   Copyright (c) 2017 (https://www.mgt-commerce.com)
 */

namespace Mgt\Varnish\Controller\Adminhtml\Purge;

class Single extends \Magento\Backend\App\Action
{
    public function execute()
    {
        $request = $this->getRequest();
        $url = trim($request->getParam('url'));
        if ($url) {
            try {
                $cachePurger = $this->_objectManager->get('\Magento\CacheInvalidate\Model\PurgeCache');
                $cachePurger->purgeUrlRequest($url);
                $this->messageManager->addSuccessMessage(sprintf('URL "%s" has been purged from Varnish Cache', $url));
            } catch (\Exception $e) {
                $errorMessage = $e->getMessage();
                $this->messageManager->addErrorMessage($errorMessage);
            }
        } else {
            $this->messageManager->addErrorMessage('Single Purge Url cannot be empty');
        }
        $resultRedirect = $this->resultRedirectFactory->create();
        return $resultRedirect->setPath('adminhtml/cache/index');
    }
}
