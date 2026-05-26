<?php

namespace sfsinfotech\craftmfaenforcer\migrations;

use craft\db\Migration;

class Install extends Migration
{
    public string $driver;

    public function safeUp(): bool
    {
        $this->driver = \Craft::$app->getConfig()->getDb()->driver;

        if (!$this->db->tableExists('{{%mfaenforcer_user_secrets}}')) {
            $this->createTable('{{%mfaenforcer_user_secrets}}', [
                'id'          => $this->primaryKey(),
                'userId'      => $this->integer()->notNull(),
                'secret'      => $this->string(255)->notNull(),
                'enabled'     => $this->boolean()->notNull()->defaultValue(false),
                'dateCreated' => $this->dateTime()->notNull(),
                'dateUpdated' => $this->dateTime()->notNull(),
                'uid'         => $this->uid(),
            ]);

            $this->createIndex(null, '{{%mfaenforcer_user_secrets}}', ['userId'], true);

            $this->addForeignKey(
                null,
                '{{%mfaenforcer_user_secrets}}',
                ['userId'],
                '{{%users}}',
                ['id'],
                'CASCADE',
                null
            );
        }

        if (!$this->db->tableExists('{{%mfaenforcer_tokens}}')) {
            $this->createTable('{{%mfaenforcer_tokens}}', [
                'id' => $this->primaryKey(),
                'userId' => $this->integer()->notNull(),
                'token' => $this->string(64)->notNull(),
                'actionKey' => $this->string(64)->notNull(),
                'expiresAt' => $this->dateTime()->notNull(),
                'usedAt' => $this->dateTime()->null(),
                'dateCreated' => $this->dateTime()->notNull(),
                'dateUpdated' => $this->dateTime()->notNull(),
                'uid' => $this->uid(),
            ]);

            $this->createIndex(null, '{{%mfaenforcer_tokens}}', ['token'], true);
            $this->createIndex(null, '{{%mfaenforcer_tokens}}', ['userId', 'actionKey']);

            $this->addForeignKey(
                null,
                '{{%mfaenforcer_tokens}}',
                ['userId'],
                '{{%users}}',
                ['id'],
                'CASCADE',
                null
            );
        }

        if (!$this->db->tableExists('{{%mfaenforcer_settings}}')) {
            $this->createTable('{{%mfaenforcer_settings}}', [
                'id'                    => $this->primaryKey(),
                'enforcedGroupIds'      => $this->text()->notNull(),
                'exemptUserIds'         => $this->text()->notNull(),
                'failureLimit'          => $this->integer()->notNull()->defaultValue(5),
                'failureLockoutMinutes' => $this->integer()->notNull()->defaultValue(5),
                'protectedActions'      => $this->mediumText()->notNull(),
                'dateCreated'           => $this->dateTime()->notNull(),
                'dateUpdated'           => $this->dateTime()->notNull(),
                'uid'                   => $this->uid(),
            ]);

            $this->insert('{{%mfaenforcer_settings}}', [
                'enforcedGroupIds'      => '[]',
                'exemptUserIds'         => '[]',
                'failureLimit'          => 5,
                'failureLockoutMinutes' => 5,
                'protectedActions'      => '{}',
                'dateCreated'           => (new \DateTime())->format('Y-m-d H:i:s'),
                'dateUpdated'           => (new \DateTime())->format('Y-m-d H:i:s'),
                'uid'                   => \craft\helpers\StringHelper::UUID(),
            ]);
        }

        return true;
    }

    public function safeDown(): bool
    {
        $this->dropTableIfExists('{{%mfaenforcer_settings}}');
        $this->dropTableIfExists('{{%mfaenforcer_tokens}}');
        $this->dropTableIfExists('{{%mfaenforcer_user_secrets}}');
        return true;
    }
}
