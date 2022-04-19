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
 * Copyright © 2013-2022, Kenneth Leung. All rights reserved. */

package czlab.twisty;

import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManagerFactorySpi;
import java.security.KeyStore;

/**
 * A simple trust manager.
 *
 */
@SuppressWarnings("unused")
public abstract class SSLTrustMgrFactory extends TrustManagerFactorySpi {

  @Override
  public void engineInit(ManagerFactoryParameters p) {}

  @Override
  public void engineInit(KeyStore ks) {}

}

