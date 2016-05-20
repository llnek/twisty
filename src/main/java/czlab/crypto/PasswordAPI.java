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
 * Copyright (c) 2013-2016, Kenneth Leung. All rights reserved. */

package czlab.crypto;


import org.apache.commons.lang3.tuple.ImmutablePair;

/**
 *
 * @author kenl
 *
 */
public interface PasswordAPI {

  /**
   * Does this password hashed to match the target?
   *
   * @param targetHashed
   * @return
   */
  public boolean validateHash(String targetHashed);
  public char[] toCharArray();

  /**
   * A tuple(2) ['hashed value' 'salt']
   *
   * @return
   */
  public ImmutablePair<String,String> stronglyHashed();

  /**
   * A tuple(2) ['hashed value' 'salt']
   *
   * @return
   */
  public ImmutablePair<String,String> hashed();

  public String encoded();
  public String text();

}


