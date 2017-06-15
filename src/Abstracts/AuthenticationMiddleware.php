<?php

/*
 * This file is part of Slim Authentication core
 *
 * PHP version 5.3
 *
 * @category    Authentication
 * @package     SlimPower
 * @subpackage  Authentication
 * @author      Matias Nahuel Améndola <soporte.esolutions@gmail.com>
 * @link        https://github.com/MatiasNAmendola/slimpower-auth-core
 * @license     http://www.opensource.org/licenses/mit-license.html MIT License
 * @copyright   2016
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

namespace SlimPower\Authentication\Abstracts;

use SlimPower\Authentication\Error;
use SlimPower\Authentication\Callables\RequestMethodRule;
use SlimPower\Authentication\Callables\RequestPathRule;

abstract class AuthenticationMiddleware extends \Slim\Middleware {

    protected $error = null; /* Last error */
    protected $rules = array();
    protected $options = array();
    protected $data = array();

    /**
     * Fetch data
     * @return mixed Data
     */
    abstract protected function fetchData();

    /**
     * Get Params
     * @return array Params
     */
    abstract protected function getParams();

    /**
     * Constructor
     * @param array $options Options
     * @throws \RuntimeException
     */
    public function __construct($options = array()) {
        $this->setOptions($options);

        /* Setup stack for rules */
        $this->rules = new \SplStack;

        /* Store passed in options overwriting any defaults */
        $this->hydrate($options);

        /* If nothing was passed in options add default rules. */
        if (!isset($this->options["rules"])) {
            $this->addRule(new RequestMethodRule(array(
                "passthrough" => array("OPTIONS")
            )));
        }

        /* If path was given in easy mode add rule for it. */
        if (null !== ($this->options["path"])) {
            $this->addRule(new RequestPathRule(array(
                "path" => $this->options["path"]
            )));
        }

        $this->validAuthenticator();
    }

    private function validAuthenticator() {
        /* There must be an authenticator either passed via options */
        if (null === $this->options["authenticator"]) {
            throw new \RuntimeException("Authenticator must be given");
        }

        $className = get_class($this->options["authenticator"]);
        $class = new \ReflectionClass($className);

        $this->validAuthenticatorStructure($class);
    }
    
    protected function validAuthenticatorStructure(\ReflectionClass $class) {
        if (!$class->implementsInterface('SlimPower\Authentication\Interfaces\AuthenticatorInterface')) {
            throw new \RuntimeException("Invalid Authenticator");
        }
    }

    protected function setOptions($options = array()) {
        $base = array(
            "authenticator" => null,
            "callback" => null,
            "environment" => "HTTP_AUTHORIZATION",
            "path" => null,
            "relaxed" => array("localhost", "127.0.0.1"),
            "secure" => true,
            "error" => null,
            "warningPaths" => null
        );

        $this->options = array_replace_recursive($base, $options);
    }

    /**
     * Call the middleware
     */
    public function call() {
        /* If rules say we should not authenticate call next and return. */
        if (false === $this->shouldAuthenticate()) {
            $this->next->call();
            return;
        }

        $this->checkSecure();

        $freePass = $this->hasFreePass();

        /* If userdata cannot be found return with 401 Unauthorized. */
        if ((false === $this->data = $this->fetchData()) && !$freePass) {
            $this->callError();
            return;
        }

        if (false === $this->data && $freePass) {
            $this->next->call();
            return;
        }

        /* Check if user authenticates. */
        $authenticator = $this->options["authenticator"];

        if (false === $authenticator($this->data)) {
            $this->error = $authenticator->getError();
            $this->callError();
            return;
        }
        
        $this->app->userData = $authenticator->getData();

        if (!$this->customValidation()) {
            $this->callError();
            return;
        }

        /* If callback returns false return with 401 Unauthorized. */
        if (is_callable($this->options["callback"])) {
            $params = $this->getParams();
            if (false === $this->options["callback"]($params)) {
                $this->error = new Error();
                $this->error->setDescription("Callback returned false");
                $this->callError();
                return;
            }
        }

        /* Everything ok, call next middleware. */
        $this->next->call();
    }

    protected function customValidation() {
        return true;
    }

    /**
     * HTTP allowed only if secure is false or server is in relaxed array.
     * @throws \RuntimeException
     */
    private function checkSecure() {
        $environment = $this->app->environment;
        $scheme = $environment["slim.url_scheme"];

        if ("https" !== $scheme && true === $this->options["secure"]) {
            if (!in_array($environment["SERVER_NAME"], $this->options["relaxed"])) {
                $message = sprintf(
                        "Insecure use of middleware over %s denied by configuration.", strtoupper($scheme)
                );
                throw new \RuntimeException($message);
            }
        }
    }

    private function hasFreePass() {
        $uri = $this->app->request->getResourceUri();
        $freePass = false;

        /* If request path is matches warningPaths should not authenticate. */
        foreach ((array) $this->options["warningPaths"] as $warningPaths) {
            $warningPaths = rtrim($warningPaths, "/");

            if (!!preg_match("@^{$warningPaths}(/.*)?$@", $uri)) {
                $freePass = true;
                break;
            }
        }

        return $freePass;
    }

    /**
     * Hydate options from given array
     *
     * @param array $data Array of options.
     * @return self
     */
    private function hydrate($data = array()) {
        foreach ($data as $key => $value) {
            $method = "set" . ucfirst($key);
            if (method_exists($this, $method)) {
                call_user_func(array($this, $method), $value);
            }
        }
    }

    /**
     * Check if middleware should authenticate
     *
     * @return boolean True if middleware should authenticate.
     */
    private function shouldAuthenticate() {
        /* If any of the rules in stack return false will not authenticate */
        foreach ($this->rules as $callable) {
            if (false === $callable($this->app)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Call the error handler if it exists
     *
     * @return void
     */
    public function callError() {
        if (!($this->error instanceof Error)) {
            $this->error = new Error();
        }
        
        $status = $this->error->getStatus();
        $this->app->response->status($status);
        
        if (is_callable($this->options["error"])) {
            $this->options["error"]($this->error);
        }
    }

    public function getAuthenticator() {
        return $this->options["authenticator"];
    }

    public function setAuthenticator($authenticator) {
        $this->options["authenticator"] = $authenticator;
        return $this;
    }

    /**
     * Get path where middleware is be binded to
     *
     * @return string
     */
    public function getPath() {
        return $this->options["path"];
    }

    /**
     * Set path where middleware should be binded to
     * 
     * @return self
     */
    public function setPath($path) {
        $this->options["path"] = $path;
        return $this;
    }

    public function getWarningPaths() {
        return $this->options["warningPaths"];
    }

    /**
     * Get the environment name where to search the token from
     *
     * @return string Name of environment variable.
     */
    public function getEnvironment() {
        return $this->options["environment"];
    }

    /**
     * Set the environment name where to search the token from
     *
     * @return self
     */
    public function setEnvironment($environment) {
        $this->options["environment"] = $environment;
        return $this;
    }

    /**
     * Get the secure flag
     *
     * @return boolean
     */
    public function getSecure() {
        return $this->options["secure"];
    }

    /**
     * Set the secure flag
     *
     * @return self
     */
    public function setSecure($secure) {
        $this->options["secure"] = !!$secure;
        return $this;
    }

    /**
     * Get hosts where secure rule is relaxed
     *
     * @return string
     */
    public function getRelaxed() {
        return $this->options["relaxed"];
    }

    /**
     * Set hosts where secure rule is relaxed
     *
     * @return self
     */
    public function setRelaxed(array $relaxed) {
        $this->options["relaxed"] = $relaxed;
        return $this;
    }

    /**
     * Get the callback
     *
     * @return string
     */
    public function getCallback() {
        return $this->options["callback"];
    }

    /**
     * Set the callback
     *
     * @return self
     */
    public function setCallback($callback) {
        $this->options["callback"] = $callback;
        return $this;
    }

    /**
     * Get the error handler
     *
     * @return string
     */
    public function getError() {
        return $this->options["error"];
    }

    /**
     * Set the error handler
     *
     * @return self
     */
    public function setError($error) {
        $this->options["error"] = $error;
        return $this;
    }

    /**
     * Get the rules stack
     *
     * @return \SplStack
     */
    public function getRules() {
        return $this->rules;
    }

    /**
     * Set all rules in the stack
     *
     * @return self
     */
    public function setRules(array $rules) {
        /* Clear the stack */
        unset($this->rules);
        $this->rules = new \SplStack;

        /* Add the rules */
        foreach ($rules as $callable) {
            $this->addRule($callable);
        }

        return $this;
    }

    /**
     * Add rule to the stack
     *
     * @param callable $callable Callable which returns a boolean.
     * @return self
     */
    public function addRule($callable) {
        $this->rules->push($callable);
        return $this;
    }

}
