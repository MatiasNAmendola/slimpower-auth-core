<?php

/**
 * This file is part of Slim Authentication core
 *
 * @category   Authentication
 * @package    SlimPower
 * @subpackage Authentication
 * @author     Matias Nahuel Améndola <soporte.esolutions@gmail.com>
 * @link       https://github.com/MatiasNAmendola/slimpower-auth-core
 * @license    https://github.com/MatiasNAmendola/slimpower-auth-core/blob/master/LICENSE.md
 * @since      0.0.1
 * 
 * MIT LICENSE
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

namespace SlimPower\Authentication\Callables;

use SlimPower\Authentication\Abstracts\LoginCallableAuthenticator;
use SlimPower\Authentication\Interfaces\LoginAuthenticatorInterface;

class PdoAuthenticator extends LoginCallableAuthenticator implements LoginAuthenticatorInterface {

    /**
     * Constructor
     * @param \SlimPower\Slim\Slim $app SlimPower instance
     * @param array $options Options
     */
    public function __construct(\SlimPower\Slim\Slim $app, array $options = array()) {
        parent::__construct($app, $options);
    }

    /**
     * Get default options
     * @return array
     */
    protected function getDefaultOptions() {
        $options = array(
            "table" => "users",
            "user" => "user",
            "hash" => "hash",
            "show" => array() /* fields to show */
        );

        return $options;
    }

    /**
     * Authenticate
     * @param string $username Username
     * @param string $password Password
     * @return array|null User data or null
     */
    public function authenticate($username, $password) {
        if (!$this->hasPDO()) {
            return NULL;
        }

        $sql = $this->sql();

        /* @var $pdo \PDO */
        $pdo = $this->options["pdo"];
        $statement = $pdo->prepare($sql);
        $statement->execute(array($username));

        $success = false;
        $user = $statement->fetch(\PDO::FETCH_ASSOC);

        if ($user) {
            $success = password_verify($password, $user[$this->options["hash"]]);
        }

        if (!$success) {
            $this->error = new \SlimPower\Authentication\Error();
            return null;
        } else {
            $data = array();

            foreach ($this->options["show"] as $fieldname) {
                if (array_key_exists($fieldname, $user)) {
                    $data[$fieldname] = $user[$fieldname];
                }
            }

            return $data;
        }
    }

    public function sql() {
        if (!$this->hasPDO()) {
            return NULL;
        }

        $driver = $this->options["pdo"]->getAttribute(\PDO::ATTR_DRIVER_NAME);

        /* Workaround to test without sqlsrv with Travis */
        if (defined("__PHPUNIT_ATTR_DRIVER_NAME__")) {
            $driver = __PHPUNIT_ATTR_DRIVER_NAME__;
        }

        if ("sqlsrv" === $driver) {
            $sql = "SELECT TOP 1 *
                 FROM {$this->options['table']}
                 WHERE {$this->options['user']} = ?";
        } else {
            $sql = "SELECT *
                 FROM {$this->options['table']}
                 WHERE {$this->options['user']} = ?
                 LIMIT 1";
        }

        return preg_replace("!\s+!", " ", $sql);
    }

    private function hasPDO() {
        $instanced = FALSE;

        if (isset($this->options["pdo"]) && !is_null($this->pdo)) {
            if ($this->options["pdo"] instanceof \PDO) {
                $instanced = TRUE;
            }
        }

        return $instanced;
    }

}
