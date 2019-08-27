<?php

namespace CasbinAdapter\ZendDb\Tests;

use Casbin\Enforcer;
use CasbinAdapter\ZendDb\Adapter;
use PHPUnit\Framework\TestCase;
use Zend\Db\TableGateway\TableGateway;
use Zend\Db\Adapter\Adapter as ZendDbAdapter;
use Zend\Db\Sql\Ddl\DropTable;
use Zend\Db\Sql\Ddl\CreateTable;
use Zend\Db\Sql\Ddl\Column\Varchar;
use Zend\Db\Sql\Sql;

class AdapterTest extends TestCase
{
    protected $config = [];

    protected $tableName = 'casbin_rule';

    public $initialized = false;

    protected function initConfig()
    {
        $this->config = [
            'driver' => 'Pdo_Mysql', // Mysqli, Sqlsrv, Pdo_Sqlite, Pdo_Mysql, Pdo(= Other PDO Driver)
            'hostname' => $this->env('DB_PORT', '127.0.0.1'),
            'database' => $this->env('DB_DATABASE', 'casbin'),
            'username' => $this->env('DB_USERNAME', 'root'),
            'password' => $this->env('DB_PASSWORD', ''),
            'port' => $this->env('DB_PORT', 3306),
        ];
    }

    protected function initialize()
    {
        if ($this->initialized) {
            return;
        }

        $this->initConfig();

        $zendDbAdapter = new ZendDbAdapter($this->config);
        $tableGateway = new TableGateway($this->tableName, $zendDbAdapter);

        $ddl = new DropTable($this->tableName);
        // Existence of $adapter is assumed.
        $sql = new Sql($zendDbAdapter);

        try {
            $zendDbAdapter->query(
                $sql->getSqlStringForSqlObject($ddl),
                $zendDbAdapter::QUERY_MODE_EXECUTE
            );
        } catch (\Exception $e) {
        }

        $table = new CreateTable($this->tableName);
        $table->addColumn(new Varchar('ptype', 255));
        $table->addColumn(new Varchar('v0', 255, true));
        $table->addColumn(new Varchar('v1', 255, true));
        $table->addColumn(new Varchar('v2', 255, true));
        $table->addColumn(new Varchar('v3', 255, true));
        $table->addColumn(new Varchar('v4', 255, true));
        $table->addColumn(new Varchar('v5', 255, true));

        $zendDbAdapter->query(
            $sql->getSqlStringForSqlObject($table),
            $zendDbAdapter::QUERY_MODE_EXECUTE
        );
        $tableGateway->delete('1 = 1');

        $tableGateway->insert(['ptype' => 'p', 'v0' => 'alice', 'v1' => 'data1', 'v2' => 'read']);
        $tableGateway->insert(['ptype' => 'p', 'v0' => 'bob', 'v1' => 'data2', 'v2' => 'write']);
        $tableGateway->insert(['ptype' => 'p', 'v0' => 'data2_admin', 'v1' => 'data2', 'v2' => 'read']);
        $tableGateway->insert(['ptype' => 'p', 'v0' => 'data2_admin', 'v1' => 'data2', 'v2' => 'write']);
        $tableGateway->insert(['ptype' => 'g', 'v0' => 'alice', 'v1' => 'data2_admin']);
    }

    protected function getEnforcer($adapter = null)
    {
        $this->initialize();

        if (!$adapter) {
            $adapter = Adapter::newAdapter($this->config);
        }

        return new Enforcer(__DIR__.'/rbac_model.conf', $adapter);
    }

    public function testLoadPolicy()
    {
        $e = $this->getEnforcer();
        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $this->assertFalse($e->enforce('bob', 'data1', 'read'));
        $this->assertTrue($e->enforce('bob', 'data2', 'write'));
        $this->assertTrue($e->enforce('alice', 'data2', 'read'));
        $this->assertTrue($e->enforce('alice', 'data2', 'write'));
    }

    public function testLoadPolicyForGivenTableGateway()
    {
        $this->initialize();
        $e = $this->getEnforcer(
            Adapter::newAdapter(
                new TableGateway(
                    $this->tableName,
                    new ZendDbAdapter($this->config)
                )
            )
        );

        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $this->assertFalse($e->enforce('bob', 'data1', 'read'));
        $this->assertTrue($e->enforce('bob', 'data2', 'write'));
        $this->assertTrue($e->enforce('alice', 'data2', 'read'));
        $this->assertTrue($e->enforce('alice', 'data2', 'write'));
    }

    public function testLoadPolicyForGivenZendDbAdapter()
    {
        $this->initialize();

        $e = $this->getEnforcer(
            Adapter::newAdapter(
                new ZendDbAdapter($this->config)
            )
        );

        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $this->assertFalse($e->enforce('bob', 'data1', 'read'));
        $this->assertTrue($e->enforce('bob', 'data2', 'write'));
        $this->assertTrue($e->enforce('alice', 'data2', 'read'));
        $this->assertTrue($e->enforce('alice', 'data2', 'write'));
    }

    public function testAddPolicy()
    {
        $e = $this->getEnforcer();
        $this->assertFalse($e->enforce('eve', 'data3', 'read'));
        $e->addPermissionForUser('eve', 'data3', 'read');
        $this->assertTrue($e->enforce('eve', 'data3', 'read'));
    }

    public function testSavePolicy()
    {
        $e = $this->getEnforcer();
        $this->assertFalse($e->enforce('alice', 'data4', 'read'));
        $model = $e->getModel();
        $model->clearPolicy();
        $model->addPolicy('p', 'p', ['alice', 'data4', 'read']);
        $adapter = $e->getAdapter();
        $adapter->savePolicy($model);
        $this->assertTrue($e->enforce('alice', 'data4', 'read'));
    }

    public function testRemovePolicy()
    {
        $e = $this->getEnforcer();
        $this->assertFalse($e->enforce('alice', 'data5', 'read'));
        $e->addPermissionForUser('alice', 'data5', 'read');
        $this->assertTrue($e->enforce('alice', 'data5', 'read'));
        $e->deletePermissionForUser('alice', 'data5', 'read');
        $this->assertFalse($e->enforce('alice', 'data5', 'read'));
    }

    public function testRemoveFilteredPolicy()
    {
        $e = $this->getEnforcer();
        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $e->removeFilteredPolicy(1, 'data1');
        $this->assertFalse($e->enforce('alice', 'data1', 'read'));
        $this->assertTrue($e->enforce('bob', 'data2', 'write'));
        $this->assertTrue($e->enforce('alice', 'data2', 'read'));
        $this->assertTrue($e->enforce('alice', 'data2', 'write'));
        $e->removeFilteredPolicy(1, 'data2', 'read');
        $this->assertTrue($e->enforce('bob', 'data2', 'write'));
        $this->assertFalse($e->enforce('alice', 'data2', 'read'));
        $this->assertTrue($e->enforce('alice', 'data2', 'write'));
        $e->removeFilteredPolicy(2, 'write');
        $this->assertFalse($e->enforce('bob', 'data2', 'write'));
        $this->assertFalse($e->enforce('alice', 'data2', 'write'));
    }

    protected function env($key, $default = null)
    {
        $value = getenv($key);
        if (is_null($default)) {
            return $value;
        }

        return false === $value ? $default : $value;
    }
}
