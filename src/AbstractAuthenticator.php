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

namespace SlimPower\Authentication;

abstract class AbstractAuthenticator implements Interfaces\AuthenticatorInterface {

    /**
     * SlimPower instance
     * @var \SlimPower\Slim\Slim 
     */
    protected $app = null;

    /**
     * Options
     * @var array 
     */
    protected $options = array();

    /**
     * Userdata
     * @var array 
     */
    protected $data = array();

    /**
     * Last error or null
     * @var \SlimPower\Authentication\Error|null 
     */
    protected $error = null;

    /**
     * Constructor
     * @param \SlimPower\Slim\Slim $app SlimPower instance
     * @param array $options Options
     */
    public function __construct(\SlimPower\Slim\Slim $app, array $options = array()) {
        $this->app = $app;

        /* Default options. */
        $this->options = $this->getDefaultOptions();

        if (is_array($options)) {
            $this->options = array_merge($this->options, $options);
        }
    }

    /**
     * Get data
     * @return array
     */
    public function getData() {
        return $this->data;
    }

    /**
     * Get last error
     * @return \SlimPower\Authentication\Error|null
     */
    public function getError() {
        return $this->error;
    }

    /**
     * @return array Default options
     */
    abstract protected function getDefaultOptions();

    /**
     * Authenticate
     * @param array $arguments Arguments
     * @return array|null User data or null
     */
    abstract protected function authenticate(array $arguments);

    /**
     * Invoke
     * @param array $arguments Arguments
     * @return bool
     */
    public function __invoke(array $arguments) {
        $data = $this->authenticate($arguments);

        if (!is_null($data)) {
            $this->data = $data;
            $this->app->flashNow('jwtdata', $data);
            return true;
        } else {
            $this->data = array();
            $this->app->flashNow('jwtdata', null);
            return false;
        }
    }

}
