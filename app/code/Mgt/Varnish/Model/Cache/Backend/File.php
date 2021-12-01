<?php
/**
 * Copyright © 2017 MGT-Commerce GmbH. All rights reserved.
 *
 * @category    Mgt
 * @package     Mgt_Varnish
 * @copyright   Copyright (c) 2017 (https://www.mgt-commerce.com)
 */

namespace Mgt\Varnish\Model\Cache\Backend;

use Symfony\Component\Filesystem\Filesystem;

class File extends \Zend_Cache_Backend_File
{
    /**
     * @var \Magento\Framework\App\Filesystem\DirectoryList
     */
    protected $directoryList;

    /**
     * Constructor
     *
     * @param \Magento\Framework\App\Filesystem\DirectoryList
     */
    public function __construct(\Magento\Framework\App\Filesystem\DirectoryList $directoryList)
    {
        $this->directoryList = $directoryList;
        $cacheDir = $this->directoryList->getPath('cache').'/mgt/';
        $this->createCacheDirIfNotExists($cacheDir);
        $options = [
            'cache_dir'       => $cacheDir,
            'cache_file_perm' => '0775'
        ];
        return parent::__construct($options);
    }

    protected function createCacheDirIfNotExists($cacheDir)
    {
        $filesystem = new Filesystem();
        $filesystem->mkdir($cacheDir);
    }
}