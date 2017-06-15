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

use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;

abstract class TokenAuthMiddleware extends AuthenticationMiddleware {

    const KEY_TOKEN = 'token';

    protected $logger;

    protected function setOptions($options = array()) {
        parent::setOptions($options);

        $base = array(
            "cookie" => self::KEY_TOKEN
        );

        $this->options = array_replace_recursive($base, $this->options);
    }

    protected function customValidation() {
        $token = $this->data[self::KEY_TOKEN];
        $details = '';

        /* If token cannot be decoded return with 401 Unauthorized. */
        if (false === $decoded = $this->decodeToken($token, $details)) {
            if (!empty($details)) {
                $this->error = new \SlimPower\Authentication\Error();
                $this->error->setDescription($details);

                $this->log(LogLevel::WARNING, $details, array($token));
            }

            return false;
        } else {
            $this->data['decoded'] = $decoded;

            /* Everything ok, add custom property! */
            $this->app->token = $this->data[self::KEY_TOKEN];

            return true;
        }
    }

    /**
     * Get Params
     * @return array Params
     */
    protected function getParams() {
        $params = array("decoded" => $this->data['decoded'], "app" => $this->app);
        return $params;
    }

    /**
     * Fetch the access token
     *
     * @return string|false Base64 encoded JSON Web Token or false if not found.
     */
    public function fetchData() {
        /* If using PHP in CGI mode and non standard environment */
        if (isset($_SERVER[$this->options["environment"]])) {
            $message = "Using token from environent";
            $header = $_SERVER[$this->options["environment"]];
        } else {
            $message = "Using token from request header";
            $header = $this->app->request->headers("Authorization");
        }

        $matches = null;

        if (preg_match("/Bearer\s+(.*)$/i", $header, $matches)) {
            $this->log(LogLevel::DEBUG, $message);
            return array(self::KEY_TOKEN => $matches[1]);
        }

        /* Bearer not found, try a cookie. */
        if ($this->app->getCookie($this->options["cookie"])) {
            $this->log(LogLevel::DEBUG, "Using token from cookie");
            $token = $this->app->getCookie($this->options["cookie"]);
            return array(self::KEY_TOKEN => $token);
        }

        /* If everything fails log and return false. */
        $message = "Token not found";

        $this->error = new \SlimPower\Authentication\Error();
        $this->error->setDescription($message);

        $this->log(LogLevel::WARNING, $message);
        return false;
    }

    /**
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

use Psr\Log\LogLevel;

abstract class TokenAuthMiddleware extends AuthenticationMiddleware {

    const KEY_TOKEN = 'token';

    protected function setOptions($options = array()) {
        parent::setOptions($options);

        $base = array(
            "cookie" => self::KEY_TOKEN
        );

        $this->options = array_replace_recursive($base, $this->options);
    }

    protected function customValidation() {
        $token = $this->data[self::KEY_TOKEN];
        $details = '';

        /* If token cannot be decoded return with 401 Unauthorized. */
        if (false === $decoded = $this->decodeToken($token, $details)) {
            if (!empty($details)) {
                $this->error = new \SlimPower\Authentication\Error();
                $this->error->setDescription($details);

                $this->log(LogLevel::WARNING, $details, array($token));
            }

            return false;
        } else {
            $this->data['decoded'] = $decoded;

            /* Everything ok, add custom property! */
            $this->app->token = $this->data[self::KEY_TOKEN];

            return true;
        }
    }

    /**
     * Get Params
     * @return array Params
     */
    protected function getParams() {
        $params = array("decoded" => $this->data['decoded'], "app" => $this->app);
        return $params;
    }

    /**
     * Fetch the access token
     *
     * @return string|false Base64 encoded JSON Web Token or false if not found.
     */
    public function fetchData() {
        /* If using PHP in CGI mode and non standard environment */
        if (isset($_SERVER[$this->options["environment"]])) {
            $message = "Using token from environent";
            $header = $_SERVER[$this->options["environment"]];
        } else {
            $message = "Using token from request header";
            $header = $this->app->request->headers("Authorization");
        }

        $matches = null;

        if (preg_match("/Bearer\s+(.*)$/i", $header, $matches)) {
            $this->log(LogLevel::DEBUG, $message);
            return array(self::KEY_TOKEN => $matches[1]);
        }

        /* Bearer not found, try a cookie. */
        if ($this->app->getCookie($this->options["cookie"])) {
            $this->log(LogLevel::DEBUG, "Using token from cookie");
            $token = $this->app->getCookie($this->options["cookie"]);
            return array(self::KEY_TOKEN => $token);
        }

        /* If everything fails log and return false. */
        $message = "Token not found";

        $this->error = new \SlimPower\Authentication\Error();
        $this->error->setDescription($message);

        $this->log(LogLevel::WARNING, $message);
        return false;
    }

    /**
     * Retrieves the token payload
     * 
     * @param string $token Authentication token
     * @param string $details Details, if error exist
     * 
     * @return mixed|boolean
     */
    abstract public function decodeToken($token, &$details);

    /**
     * Get the cookie name where to search the token from
     *
     * @return string
     */
    public function getCookie() {
        return $this->options["cookie"];
    }

    /**
     * Set the cookie name where to search the token from
     *
     * @return self
     */
    public function setCookie($cookie) {
        $this->options["cookie"] = $cookie;
        return $this;
    }

}
