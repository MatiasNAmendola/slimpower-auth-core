<?php

/**
 * This file is part of Slim HTTP Basic Authentication middleware
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

class DemoAuthenticator extends AbstractAuthenticator implements Interfaces\AuthenticatorInterface {

    const KEY_USER = "user";
    const KEY_PWD = "password";
    const VAL_USER = "admin";
    const VAL_PWD = "demo";

    /**
     * Get default options
     * @return array
     */
    protected function getDefaultOptions() {
        return array();
    }

    /**
     * Authenticate
     * @param array $arguments Arguments
     * @return array|null User data or null
     */
    protected function authenticate(array $arguments) {
        $success = $arguments[self::KEY_USER] == self::VAL_USER && $arguments[self::KEY_PWD] == self::VAL_PWD;

        if (!$success) {
            $this->error = new \SlimPower\Authentication\Error();
            return null;
        } else {
            return array('user' => self::VAL_USER);
        }
    }

}
