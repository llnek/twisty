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

package czlab.twisty;

import javax.activation.DataSource;
import static czlab.xlib.CU.nsb;
import czlab.xlib.XData;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Streamable Data Source.
 *
 * @author Kenneth Leung
 *
 */
public class SDataSource implements DataSource {

  private String _ctype= "";
  private XData _data;

  /**/
  public SDataSource(byte[] content, String contentType) {
    _data= new XData(content);
    _ctype= nsb(contentType);
  }

  /**/
  public SDataSource(File file, String contentType) {
    _data= new XData(file,false);
    _ctype= nsb(contentType);
  }

  /**/
  public SDataSource(XData content, String contentType) {
    _ctype= nsb(contentType);
    _data= content;
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
  public SDataSource(XData content) {
    this(content, "");
  }

  @Override
  public String getContentType() { return _ctype; }

  @Override
  public String getName() { return "Unknown"; }

  @Override
  public OutputStream getOutputStream() throws IOException {
    throw new IOException("Not implemented");
  }

  @Override
  public InputStream getInputStream() throws IOException {
    return _data.stream();
  }

}


