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


import java.io.ByteArrayInputStream;
import javax.activation.DataSource;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import static czlab.xlib.CU.nsb;
import czlab.xlib.XStream;

/**
 * Secured Data Source.
 *
 * @author kenl
 *
 */
public class SDataSource implements DataSource {

  private String _ctype= "";
  private byte[] _bits;
  private File _fn;

  /**/
  public SDataSource(File content, String contentType) {
    _ctype= nsb(contentType);
    _fn= content;
  }

  /**/
  public SDataSource(byte[] content, String contentType) {
    _ctype= nsb(contentType);
    _bits= content;
  }

  /**/
  public SDataSource(File content) {
    this(content, "");
  }

  /**/
  public SDataSource(byte[] content) {
    this(content, "");
  }

  /**/
  public String getContentType() { return _ctype; }

  /**/
  public String getName() { return "Unknown"; }

  /**/
  public OutputStream getOutputStream() throws IOException {
    throw new IOException("Not implemented");
  }

  /**/
  public InputStream getInputStream() {
    return (_fn==null)
      ? new ByteArrayInputStream(_bits) : new XStream(_fn);
  }

}


