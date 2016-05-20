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

package com.zotohlab.frwk.crypto;


import static com.zotohlab.frwk.util.CU.nsb;
import com.zotohlab.frwk.io.XStream;
import javax.activation.DataSource;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 *
 * @author kenl
 *
 */
public class SDataSource implements DataSource {

  private String _ctype= "";
  private byte[] _bits;
  private File _fn;

  /**
   * @param content
   * @param contentType
   */
  public SDataSource(File content, String contentType) {
    _ctype= nsb(contentType);
    _fn= content;
  }

  /**
   * @param content
   * @param contentType
   */
  public SDataSource(byte[] content, String contentType) {
    _ctype= nsb(contentType);
    _bits= content;
  }

  /**
   * @param content
   */
  public SDataSource(File content) {
    this(content, "");
  }

  /**
   * @param content
   */
  public SDataSource(byte[] content) {
    this(content, "");
  }

  public String getContentType() { return _ctype; }

  public InputStream getInputStream() {
    return (_fn==null) ? new ByteArrayInputStream(_bits) : new XStream(_fn);
  }

  public String getName() { return "Unknown"; }

  public OutputStream getOutputStream() throws IOException {
    throw new IOException("Not implemented");
  }

}


