<?php
/**
 * Copyright © 2017 MGT-Commerce GmbH. All rights reserved.
 *
 * @category    Mgt
 * @package     Mgt_Varnish
 * @copyright   Copyright (c) 2017 (https://www.mgt-commerce.com)
 */

namespace Mgt\Varnish\Setup;

use Magento\Framework\Setup\InstallSchemaInterface;
use Magento\Framework\Setup\ModuleContextInterface;
use Magento\Framework\Setup\SchemaSetupInterface;

/**
 * @codeCoverageIgnore
 */
class InstallSchema implements InstallSchemaInterface
{
    /**
     * {@inheritdoc}
     */
    public function install(SchemaSetupInterface $setup, ModuleContextInterface $context)
    {
        $installer = $setup;
        $installer->startSetup();

        $table = $installer->getConnection()
            ->newTable(
                $installer->getTable('mgt_varnish_url')
            )
            ->addColumn(
                'url_id',
                \Magento\Framework\DB\Ddl\Table::TYPE_INTEGER,
                null,
                ['identity' => true, 'unsigned' => true, 'nullable' => false, 'primary' => true],
                'URL ID'
            )
            ->addColumn(
                'store_id',
                \Magento\Framework\DB\Ddl\Table::TYPE_SMALLINT,
                null,
                ['unsigned' => true],
                'Store ID'
            )
            ->addColumn(
                'path',
                \Magento\Framework\DB\Ddl\Table::TYPE_TEXT,
                128,
                ['nullable' => false, 'default' => null],
                'Path'
            )
            ->addColumn(
                'cache_lifetime',
                \Magento\Framework\DB\Ddl\Table::TYPE_INTEGER,
                null,
                ['unsigned' => true, 'nullable' => false],
                'Cache Lifetime'
            )
            ->addColumn(
                'cache_expired_at',
                \Magento\Framework\DB\Ddl\Table::TYPE_DATETIME,
                null,
                ['nullable' => false],
                'Cache Expiration Date'
            )
            ->addColumn(
                'created_at',
                \Magento\Framework\DB\Ddl\Table::TYPE_TIMESTAMP,
                null,
                ['nullable' => false, 'default' => \Magento\Framework\DB\Ddl\Table::TIMESTAMP_INIT],
                'Creation Time'
            )
            ->addIndex(
                $installer->getIdxName('mgt_varnish_url_queue', ['store_id']),
                ['store_id']
            )
            ->addForeignKey(
                $installer->getFkName('mgt_varnish_url', 'store_id', 'store', 'store_id'),
                'store_id',
                $installer->getTable('store'),
                'store_id',
                \Magento\Framework\DB\Ddl\Table::ACTION_CASCADE
            )
            ->setComment('MGT Varnish Url');

        $installer->getConnection()->createTable($table);

        $table = $installer->getConnection()
            ->newTable(
                $installer->getTable('mgt_varnish_url_tag')
            )
            ->addColumn(
                'url_id',
                \Magento\Framework\DB\Ddl\Table::TYPE_INTEGER,
                null,
                ['unsigned' => true, 'nullable' => false],
                'URL ID'
            )
            ->addColumn(
                'tag',
                \Magento\Framework\DB\Ddl\Table::TYPE_TEXT,
                128,
                ['nullable' => false, 'default' => null],
                'Tag'
            )
            ->addIndex(
                $installer->getIdxName('mgt_varnish_url_tag', ['url_id']),
                ['url_id']
            )
            ->addForeignKey(
                $installer->getFkName('mgt_varnish_url_tag', 'url_id', 'mgt_varnish_url', 'url_id'),
                'url_id',
                $installer->getTable('mgt_varnish_url'),
                'url_id',
                \Magento\Framework\DB\Ddl\Table::ACTION_CASCADE
            )
            ->setComment('MGT Varnish Url Tag');

        $installer->getConnection()->createTable($table);

        $table = $installer->getConnection()
            ->newTable(
                $installer->getTable('mgt_varnish_url_queue')
            )
            ->addColumn(
                'url_id',
                \Magento\Framework\DB\Ddl\Table::TYPE_INTEGER,
                null,
                ['identity' => true, 'unsigned' => true, 'nullable' => false, 'primary' => true],
                'URL ID'
            )
            ->addColumn(
                'store_id',
                \Magento\Framework\DB\Ddl\Table::TYPE_SMALLINT,
                null,
                ['unsigned' => true],
                'Store ID'
            )
            ->addColumn(
                'path',
                \Magento\Framework\DB\Ddl\Table::TYPE_TEXT,
                128,
                ['nullable' => false, 'default' => null],
                'Path'
            )
            ->addColumn(
                'priority',
                \Magento\Framework\DB\Ddl\Table::TYPE_INTEGER,
                null,
                ['unsigned' => true, 'nullable' => false, 'default' => '0'],
                'Priority'
            )
            ->addColumn(
                'created_at',
                \Magento\Framework\DB\Ddl\Table::TYPE_TIMESTAMP,
                null,
                ['nullable' => false, 'default' => \Magento\Framework\DB\Ddl\Table::TIMESTAMP_INIT],
                'Creation Time'
            )
            ->addIndex(
                $installer->getIdxName('mgt_varnish_url_queue', ['store_id']),
                ['store_id']
            )
            ->addIndex(
                $installer->getIdxName(
                    'mgt_varnish_url_queue_store_id_path',
                    ['store_id', 'path'],
                    \Magento\Framework\DB\Adapter\AdapterInterface::INDEX_TYPE_UNIQUE
                ),
                ['store_id', 'path'],
                ['type' => \Magento\Framework\DB\Adapter\AdapterInterface::INDEX_TYPE_UNIQUE]
            )
            ->addForeignKey(
                $installer->getFkName('mgt_varnish_url_queue', 'store_id', 'store', 'store_id'),
                'store_id',
                $installer->getTable('store'),
                'store_id',
                \Magento\Framework\DB\Ddl\Table::ACTION_CASCADE
            )
            ->setComment('MGT Varnish Url Queue');

        $installer->getConnection()->createTable($table);

        $installer->endSetup();
    }
}
