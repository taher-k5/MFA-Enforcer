<?php

namespace sfsinfotech\craftmfaenforcer\web\assets\cp;

use craft\web\AssetBundle;
use craft\web\assets\cp\CpAsset as CraftCpAsset;

class CpAsset extends AssetBundle
{
    public $publishOptions = ['forceCopy' => true];

    public function init(): void
    {
        $this->sourcePath = __DIR__;
        $this->depends = [CraftCpAsset::class];
        $this->js = ['mfa-enforcer.js'];
        $this->css = ['mfa-enforcer.css'];
        parent::init();
    }
}
