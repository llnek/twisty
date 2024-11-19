/* Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright © 2013-2024, Kenneth Leung. All rights reserved. */

package czlab.twisty;

import javax.mail.Authenticator;
import javax.mail.PasswordAuthentication;

/**
 * A simple authentication object.
 */
public class DefaultAuthenticator extends Authenticator {

  private final PasswordAuthentication authentication;

  /**
   */
  public DefaultAuthenticator(final String user, final String pwd) {
    authentication = new PasswordAuthentication(user, pwd);
  }

  /**
   * Gets the authentication object that will be used to login to the mail server.
   *
   * @return object containing the login information.
   */
  @Override
  protected PasswordAuthentication getPasswordAuthentication() {
    return authentication;
  }

}

