/**
 * Copyright (c) 2013-2017, Kenneth Leung. All rights reserved.
 * The use and distribution terms for this software are covered by the
 * Eclipse Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php)
 * which can be found in the file epl-v10.html at the root of this distribution.
 * By using this software in any fashion, you are agreeing to be bound by
 * the terms of this license.
 * You must not remove this notice, or any other, from this software.
 */

package czlab.twisty;

/**
 *
 * @author Kenneth Leung
 *
 */
public interface IPassword {

  /**
   * true if the hash matches the internal value.
   */
  public boolean validateHash(String targetHashed);

  /**
   * Get the password.
   */
  public char[] toCharArray();

  /**
   * A map(2) {:hashed 'hashed value' :salt 'salt'}
   */
  public Object stronglyHashed();

  /**
   * A map(2) {:hashed 'hashed value' :salt 'salt'}
   */
  public Object hashed();

  /**
   * The encoded value.
   */
  public String encoded();

  /**
   * The text value.
   */
  public String text();

}

