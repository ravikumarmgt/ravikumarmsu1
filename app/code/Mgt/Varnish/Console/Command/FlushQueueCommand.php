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

class FlushQueueCommand extends Command
{
    /**
     * @var \Mgt\Varnish\Model\ResourceModel\UrlQueue
     */
    protected $urlQueueResource;

    /**
     * Constructor
     *
     * @param \Mgt\Varnish\Model\ResourceModel\UrlQueue $urlQueueResource
     */
    public function __construct(
        \Mgt\Varnish\Model\ResourceModel\UrlQueue $urlQueueResource
     ) {
        $this->urlQueueResource = $urlQueueResource;
        parent::__construct();
    }

    /**
     * {@inheritdoc}
     */
    protected function configure()
    {
        $this->setName('mgt-varnish:flush-queue');
        $this->setDescription('MGT Varnish Cache Flush Queue');
        parent::configure();
    }

    /**
     * {@inheritdoc}
     */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        try {
            $this->urlQueueResource->flushAll();
            $output->writeln('<info>Varnish Url Queue flushed</info>');
        } catch (\Exception $e) {
            $errorMessage = $e->getMessage();
            $output->writeln(sprintf('<error>%s</error>', $errorMessage));
            return \Magento\Framework\Console\Cli::RETURN_FAILURE;
        }
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
