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

use SlimPower\Authentication\Callables\ArrayAuthenticator;

abstract class LoginAuthMiddleware extends AuthenticationMiddleware {

    const KEY_USERNAME = 'user';
    const KEY_PASSWORD = 'password';

    protected function setOptions($options = array()) {
        parent::setOptions($options);

        $base = array(
            "users" => null,
            "realm" => "Restricted Area"
        );

        $this->options = array_replace_recursive($base, $this->options);

        /* If array of users was passed in options create an authenticator */
        if (is_array($this->options["users"])) {
            $this->options["authenticator"] = new ArrayAuthenticator($this->app, array(
                "users" => $this->options["users"]
            ));
        }
    }

    protected function validAuthenticatorInterface(\ReflectionClass $class) {
        parent::validAuthenticatorInterface($class);

        if (!$class->implementsInterface('SlimPower\Authentication\Interfaces\LoginAuthenticatorInterface')) {
            throw new \RuntimeException("Invalid Authenticator");
        }
    }

    /**
     * Get Params
     * @return array Params
     */
    protected function getParams() {
        $params = array("app" => $this->app);
        return $params;
    }

    public function getUsers() {
        return $this->options["users"];
    }

    public function getRealm() {
        return $this->options["realm"];
    }

    public function setRealm($realm) {
        $this->options["realm"] = $realm;
        return $this;
    }

}
