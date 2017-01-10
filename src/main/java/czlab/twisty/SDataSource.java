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


