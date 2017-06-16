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

class LoginNullAuthenticator extends LoginCallableAuthenticator implements LoginAuthenticatorInterface {

    const DEFAULT_ALG = 'sha256';

    protected function getDefaultOptions() {
        return array();
    }

    /**
     * Authenticate
     * @param string $username Username
     * @param string $password Password
     * @return array|null User data or null
     */
    public function authenticate($username, $password) {
        $enc = hash(self::DEFAULT_ALG, $username . $password);
        $ret = array("user" => $username, "id" => $enc);
        return $ret;
    }

}
