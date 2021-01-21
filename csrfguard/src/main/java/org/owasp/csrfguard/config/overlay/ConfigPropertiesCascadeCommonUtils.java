/*
 * The OWASP CSRFGuard Project, BSD License
 * Copyright (c) 2011, Eric Sheridan (eric@infraredsecurity.com)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     1. Redistributions of source code must retain the above copyright notice,
 *        this list of conditions and the following disclaimer.
 *     2. Redistributions in binary form must reproduce the above copyright
 *        notice, this list of conditions and the following disclaimer in the
 *        documentation and/or other materials provided with the distribution.
 *     3. Neither the name of OWASP nor the names of its contributors may be used
 *        to endorse or promote products derived from this software without specific
 *        prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.owasp.csrfguard.config.overlay;

import java.io.*;
import java.lang.reflect.*;
import java.net.URL;
import java.net.URLDecoder;
import java.security.CodeSource;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * utility methods for grouper.
 *
 * This code is copied from the <a href="https://github.com/Internet2/grouper">Grouper</a> project
 *
 * @author mchyzer
 *
 */
@SuppressWarnings({ "serial", "unchecked" })
public class ConfigPropertiesCascadeCommonUtils  {

  /**
   * get canonical path of file
   * @param file The file from which the canonical path will be extracted
   * @return the canonical path
   * @see File#getCanonicalPath()
   */
  public static String fileCanonicalPath(File file) {
    try {
      return file.getCanonicalPath();
    } catch (IOException ioe) {
      throw new RuntimeException(ioe);
    }
  }


  /**
   * compute a url of a resource
   * @param resourceName The resource name for which a URL will be built
   * @param canBeNull if can't be null, throw runtime
   * @return the URL for the resource name
   * @see ClassLoader#getResource(String)
   */
  public static URL computeUrl(String resourceName, boolean canBeNull) {
    //get the url of the navigation file
    ClassLoader cl = classLoader();

    URL url = null;

    try {
      //CH 20081012: sometimes it starts with slash and it shouldnt...
      String newResourceName = resourceName.startsWith("/") 
        ? resourceName.substring(1) : resourceName;
      url = cl.getResource(newResourceName);
    } catch (NullPointerException npe) {
      String error = "computeUrl() Could not find resource file: " + resourceName;
      throw new RuntimeException(error, npe);
    }

    if (!canBeNull && url == null) {
      throw new RuntimeException("Cant find resource: " + resourceName);
    }

    return url;
  }


  /**
   * fast class loader
   * @return the class loader
   */
  public static ClassLoader classLoader() {
    return ConfigPropertiesCascadeCommonUtils.class.getClassLoader();
  }

  /**
   * get the prefix or suffix of a string based on a separator
   * 
   * @param startString
   *          is the string to start with
   * @param separator
   *          is the separator to split on
   * @param isPrefix
   *          if thre prefix or suffix should be returned
   * 
   * @return the prefix or suffix, if the separator isnt there, return the
   *         original string
   */
  public static String prefixOrSuffix(String startString, String separator,
      boolean isPrefix) {
    String prefixOrSuffix = null;

    //no nulls
    if (startString == null) {
      return startString;
    }

    //where is the separator
    int separatorIndex = startString.indexOf(separator);

    //if none exists, dont proceed
    if (separatorIndex == -1) {
      return startString;
    }

    //maybe the separator isnt on character
    int separatorLength = separator.length();

    if (isPrefix) {
      prefixOrSuffix = startString.substring(0, separatorIndex);
    } else {
      prefixOrSuffix = startString.substring(separatorIndex + separatorLength,
          startString.length());
    }

    return prefixOrSuffix;
  }

  /**
   * Construct a class
   * @param <T> template type
   * @param theClass the class
   * @return the instance
   */
  public static <T> T newInstance(Class<T> theClass) {
    try {
      return theClass.newInstance();
    } catch (Throwable e) {
      if (theClass != null && Modifier.isAbstract(theClass.getModifiers())) {
        throw new RuntimeException("Problem with class: " + theClass + ", maybe because it is abstract!", e);        
      }
      throw new RuntimeException("Problem with class: " + theClass, e);
    }
  }
  
  /**
   * Construct a class
   * @param <T> template type
   * @param theClass the class
   * @param allowPrivateConstructor true if should allow private constructors
   * @return the instance
   */
  public static <T> T newInstance(Class<T> theClass, boolean allowPrivateConstructor) {
    if (!allowPrivateConstructor) {
      return newInstance(theClass);
    }
    try {
      Constructor<?>[] constructorArray = theClass.getDeclaredConstructors();
      for (Constructor<?> constructor : constructorArray) {
         if (constructor.getGenericParameterTypes().length == 0) {
           if (allowPrivateConstructor) {
             constructor.setAccessible(true);
           }
           return (T)constructor.newInstance();
         }
      }
      //why cant we find a constructor???
      throw new RuntimeException("Why cant we find a constructor for class: " + theClass);
    } catch (Throwable e) {
      if (theClass != null && Modifier.isAbstract(theClass.getModifiers())) {
        throw new RuntimeException("Problem with class: " + theClass + ", maybe because it is abstract!", e);        
      }
      throw new RuntimeException("Problem with class: " + theClass, e);
    }
  }


  /**
   * convert a set to a string (comma separate)
   * @param map the map to convert into a human-readable string
   * @return the String
   * @deprecated use mapToString(map)
   */
  @Deprecated
  public static String MapToString(Map map) {
    return mapToString(map);
  }

  /**
   * convert a set to a string (comma separate)
   * @param map the map to convert into a human-readable string
   * @return the String
   */
  public static String mapToString(Map map) {
    if (map == null) {
      return "null";
    }
    if (map.size() == 0) {
      return "empty";
    }
    StringBuilder result = new StringBuilder();
    boolean first = true;
    for (Object object : map.keySet()) {
      if (!first) {
        result.append(", ");
      }
      first = false;
      result.append(object).append(": ").append(map.get(object));
    }
    return result.toString();
  }

  /**
   * split a string based on a separator into an array, and trim each entry (see
   * the Commons Util trim() for more details)
   * 
   * @param input
   *          is the delimited input to split and trim
   * @param separator
   *          is what to split on
   * 
   * @return the array of items after split and trimmed, or null if input is null.  will be trimmed to empty
   */
  public static String[] splitTrim(String input, String separator) {
    return splitTrim(input, separator, true);
  }

  /**
   * split a string based on a separator into an array, and trim each entry (see
   * the Commons Util trim() for more details)
   * 
   * @param input
   *          is the delimited input to split and trim
   * @param separator
   *          is what to split on
   * 
   * @return the list of items after split and trimmed, or null if input is null.  will be trimmed to empty
   */
  public static List<String> splitTrimToList(String input, String separator) {
    if (isBlank(input)) {
      return null;
    }
    String[] array =  splitTrim(input, separator);
    return toList(array);
  }

  /**
   * split a string based on a separator into an array, and trim each entry (see
   * the Commons Util trim() for more details)
   * 
   * @param input
   *          is the delimited input to split and trim
   * @param separator
   *          is what to split on
   * @param treatAdjacentSeparatorsAsOne when true, adjacent separators are treaded as one
   * @return the array of items after split and trimmed, or null if input is null.  will be trimmed to empty
   */
  public static String[] splitTrim(String input, String separator, boolean treatAdjacentSeparatorsAsOne) {
    if (isBlank(input)) {
      return null;
    }

    //first split
    String[] items = treatAdjacentSeparatorsAsOne ? split(input, separator) : 
      splitPreserveAllTokens(input, separator);

    //then trim
    for (int i = 0; (items != null) && (i < items.length); i++) {
      items[i] = trim(items[i]);
    }

    //return the array
    return items;
  }

  /**
   * return a list of objects from varargs.  Though if there is one
   * object, and it is a list, return it.
   * 
   * @param <T>
   *            template type of the objects
   * @param objects The arguments to be returned as a List
   * @return the list or null if objects is null
   */
  @SuppressWarnings("unchecked")
  public static <T> List<T> toList(T... objects) {
    if (objects == null) {
      return null;
    }
    if (objects.length == 1 && objects[0] instanceof List) {
      return (List<T>)objects[0];
    }
    
    List<T> result = new ArrayList<T>();
    for (T object : objects) {
      result.add(object);
    }
    return result;
  }

  /**
   * make a cache with max size to cache declared methods
   */
  private static ExpirableCache<Class, Method[]> declaredMethodsCache = null;
  
  /**
   * lazy load
   * @return declared method cache
   */
  private static ExpirableCache<Class, Method[]> declaredMethodsCache() {
    if (declaredMethodsCache == null) {
      declaredMethodsCache = new ExpirableCache<Class, Method[]>(60*24);
    }
    return declaredMethodsCache;
  }


  /**
   * null safe classname method, gets the unenhanced name
   * 
   * @param object The object whose class name is desired
   * @return the classname, or null if the object was null
   */
  public static String className(Object object) {
    return object == null ? null : object.getClass().getName();
  }

  /**
   * get the decalred methods for a class, perhaps from cache
   * 
   * @param theClass the class
   * @return the declared methods
   */
  @SuppressWarnings("unused")
  private static Method[] retrieveDeclaredMethods(Class theClass) {
    Method[] methods = declaredMethodsCache().get(theClass);
    // get from cache if we can
    if (methods == null) {
      methods = theClass.getDeclaredMethods();
      declaredMethodsCache().put(theClass, methods);
    }
    return methods;
  }


  /**
   * convert an object to a int
   * @param input the object (String or Number) to parse or convert to an int
   * @return the number
   */
  public static int intValue(Object input) {
    if (input instanceof String) {
      String string = (String)input;
      return Integer.parseInt(string);
    }
    if (input instanceof Number) {
      return ((Number)input).intValue();
    }
    if (false) {
      if (input == null) {
        return 0;
      }
      if (input instanceof String || isBlank((String)input)) {
        return 0;
      }
    }
    
    throw new RuntimeException("Cannot convert to int: " + className(input));
  }

  /**
   * The name says it all.
   */
  public static final int DEFAULT_BUFFER_SIZE = 1024 * 4;

  /**
   * Unconditionally close an <code>InputStream</code>.
   * Equivalent to {@link InputStream#close()}, except any exceptions will be ignored.
   * @param input A (possibly null) InputStream
   */
  public static void closeQuietly(InputStream input) {
    if (input == null) {
      return;
    }
  
    try {
      input.close();
    } catch (IOException ioe) {
    }
  }

  /**
   * Get the contents of an <code>InputStream</code> as a String.
   * @param input the <code>InputStream</code> to read from
   * @param encoding The name of a supported character encoding. See the
   *   <a href="http://www.iana.org/assignments/character-sets">IANA
   *   Charset Registry</a> for a list of valid encoding types.
   * @return the requested <code>String</code>
   * @throws IOException In case of an I/O problem
   */
  public static String toString(InputStream input, String encoding) throws IOException {
    StringWriter sw = new StringWriter();
    copy(input, sw, encoding);
    return sw.toString();
  }

  /**
   * Copy and convert bytes from an <code>InputStream</code> to chars on a
   * <code>Writer</code>, using the specified encoding.
   * @param input the <code>InputStream</code> to read from
   * @param output the <code>Writer</code> to write to
   * @param encoding The name of a supported character encoding. See the
   * <a href="http://www.iana.org/assignments/character-sets">IANA
   * Charset Registry</a> for a list of valid encoding types.
   * @throws IOException In case of an I/O problem
   */
  public static void copy(InputStream input, Writer output, String encoding)
      throws IOException {
    InputStreamReader in = new InputStreamReader(input, encoding);
    copy(in, output);
  }

  /**
   * Copy chars from a <code>Reader</code> to a <code>Writer</code>.
   * @param input the <code>Reader</code> to read from
   * @param output the <code>Writer</code> to write to
   * @return the number of characters copied
   * @throws IOException In case of an I/O problem
   */
  public static int copy(Reader input, Writer output) throws IOException {
    char[] buffer = new char[DEFAULT_BUFFER_SIZE];
    int count = 0;
    int n = 0;
    while (-1 != (n = input.read(buffer))) {
      output.write(buffer, 0, n);
      count += n;
    }
    return count;
  }

  /**
   * do a case-insensitive matching
   * @param theEnumClass class of the enum
   * @param <E> generic type
   * 
   * @param string The name of an enum constant
   * @param exceptionOnNotFound true if exception should be thrown on not found
   * @return the enum or null or exception if not found
   * @throws RuntimeException if there is a problem
   */
  public static <E extends Enum<?>> E enumValueOfIgnoreCase(Class<E> theEnumClass, String string, 
      boolean exceptionOnNotFound) throws RuntimeException {
    
    if (!exceptionOnNotFound && isBlank(string)) {
      return null;
    }
    for (E e : theEnumClass.getEnumConstants()) {
      if (equalsIgnoreCase(string, e.name())) {
        return e;
      }
    }
    StringBuilder error = new StringBuilder(
        "Cant find " + theEnumClass.getSimpleName() + " from string: '").append(string);
    error.append("', expecting one of: ");
    for (E e : theEnumClass.getEnumConstants()) {
      error.append(e.name()).append(", ");
    }
    throw new RuntimeException(error.toString());
  
  }


  /**
   * null safe string compare
   * @param first first string, or null
   * @param second second string, or null
   * @return true if equal
   */
  public static boolean equals(String first, String second) {
    if (first == second) {
      return true;
    }
    if (first == null || second == null) {
      return false;
    }
    return first.equals(second);
  }

  /**
   * <p>Checks if a String is whitespace, empty ("") or null.</p>
   *
   * <pre>
   * isBlank(null)      = true
   * isBlank("")        = true
   * isBlank(" ")       = true
   * isBlank("bob")     = false
   * isBlank("  bob  ") = false
   * </pre>
   *
   * @param str  the String to check, may be null
   * @return <code>true</code> if the String is null, empty or whitespace
   * @since 2.0
   */
  public static boolean isBlank(String str) {
    int strLen;
    if (str == null || (strLen = str.length()) == 0) {
      return true;
    }
    for (int i = 0; i < strLen; i++) {
      if ((Character.isWhitespace(str.charAt(i)) == false)) {
        return false;
      }
    }
    return true;
  }

  /**
   * trim whitespace from string
   * @param str string to trim
   * @return trimmed string
   */
  public static String trim(String str) {
    return str == null ? null : str.trim();
  }

  /**
   * null-safe equalsignorecase
   * @param str1 first string
   * @param str2 second string
   * @return true if the strings are equal ignore case
   */
  public static boolean equalsIgnoreCase(String str1, String str2) {
    return str1 == null ? str2 == null : str1.equalsIgnoreCase(str2);
  }

  // Splitting
  //-----------------------------------------------------------------------

  /**
   * <p>Splits the provided text into an array, separators specified.
   * This is an alternative to using StringTokenizer.</p>
   *
   * <p>The separator is not included in the returned String array.
   * Adjacent separators are treated as one separator.
   * For more control over the split use the StrTokenizer class.</p>
   *
   * <p>A <code>null</code> input String returns <code>null</code>.
   * A <code>null</code> separatorChars splits on whitespace.</p>
   *
   * <pre>
   * StringUtils.split(null, *)         = null
   * StringUtils.split("", *)           = []
   * StringUtils.split("abc def", null) = ["abc", "def"]
   * StringUtils.split("abc def", " ")  = ["abc", "def"]
   * StringUtils.split("abc  def", " ") = ["abc", "def"]
   * StringUtils.split("ab:cd:ef", ":") = ["ab", "cd", "ef"]
   * </pre>
   *
   * @param str  the String to parse, may be null
   * @param separatorChars  the characters used as the delimiters,
   *  <code>null</code> splits on whitespace
   * @return an array of parsed Strings, <code>null</code> if null String input
   */
  public static String[] split(String str, String separatorChars) {
    return splitWorker(str, separatorChars, -1, false);
  }

  //-----------------------------------------------------------------------

  /**
   * <p>Splits the provided text into an array, separators specified, 
   * preserving all tokens, including empty tokens created by adjacent
   * separators. This is an alternative to using StringTokenizer.</p>
   *
   * <p>The separator is not included in the returned String array.
   * Adjacent separators are treated as separators for empty tokens.
   * For more control over the split use the StrTokenizer class.</p>
   *
   * <p>A <code>null</code> input String returns <code>null</code>.
   * A <code>null</code> separatorChars splits on whitespace.</p>
   *
   * <pre>
   * StringUtils.splitPreserveAllTokens(null, *)           = null
   * StringUtils.splitPreserveAllTokens("", *)             = []
   * StringUtils.splitPreserveAllTokens("abc def", null)   = ["abc", "def"]
   * StringUtils.splitPreserveAllTokens("abc def", " ")    = ["abc", "def"]
   * StringUtils.splitPreserveAllTokens("abc  def", " ")   = ["abc", "", def"]
   * StringUtils.splitPreserveAllTokens("ab:cd:ef", ":")   = ["ab", "cd", "ef"]
   * StringUtils.splitPreserveAllTokens("ab:cd:ef:", ":")  = ["ab", "cd", "ef", ""]
   * StringUtils.splitPreserveAllTokens("ab:cd:ef::", ":") = ["ab", "cd", "ef", "", ""]
   * StringUtils.splitPreserveAllTokens("ab::cd:ef", ":")  = ["ab", "", cd", "ef"]
   * StringUtils.splitPreserveAllTokens(":cd:ef", ":")     = ["", cd", "ef"]
   * StringUtils.splitPreserveAllTokens("::cd:ef", ":")    = ["", "", cd", "ef"]
   * StringUtils.splitPreserveAllTokens(":cd:ef:", ":")    = ["", cd", "ef", ""]
   * </pre>
   *
   * @param str  the String to parse, may be <code>null</code>
   * @param separatorChars  the characters used as the delimiters,
   *  <code>null</code> splits on whitespace
   * @return an array of parsed Strings, <code>null</code> if null String input
   * @since 2.1
   */
  public static String[] splitPreserveAllTokens(String str, String separatorChars) {
    return splitWorker(str, separatorChars, -1, true);
  }

  /**
   * Performs the logic for the <code>split</code> and 
   * <code>splitPreserveAllTokens</code> methods that return a maximum array 
   * length.
   *
   * @param str  the String to parse, may be <code>null</code>
   * @param separatorChars the separate character
   * @param max  the maximum number of elements to include in the
   *  array. A zero or negative value implies no limit.
   * @param preserveAllTokens if <code>true</code>, adjacent separators are
   * treated as empty token separators; if <code>false</code>, adjacent
   * separators are treated as one separator.
   * @return an array of parsed Strings, <code>null</code> if null String input
   */
  @SuppressWarnings("unchecked")
  private static String[] splitWorker(String str, String separatorChars, int max,
      boolean preserveAllTokens) {
    // Performance tuned for 2.0 (JDK1.4)
    // Direct code is quicker than StringTokenizer.
    // Also, StringTokenizer uses isSpace() not isWhitespace()

    if (str == null) {
      return null;
    }
    int len = str.length();
    if (len == 0) {
      return EMPTY_STRING_ARRAY;
    }
    List list = new ArrayList();
    int sizePlus1 = 1;
    int i = 0, start = 0;
    boolean match = false;
    boolean lastMatch = false;
    if (separatorChars == null) {
      // Null separator means use whitespace
      while (i < len) {
        if (Character.isWhitespace(str.charAt(i))) {
          if (match || preserveAllTokens) {
            lastMatch = true;
            if (sizePlus1++ == max) {
              i = len;
              lastMatch = false;
            }
            list.add(str.substring(start, i));
            match = false;
          }
          start = ++i;
          continue;
        }
        lastMatch = false;
        match = true;
        i++;
      }
    } else if (separatorChars.length() == 1) {
      // Optimise 1 character case
      char sep = separatorChars.charAt(0);
      while (i < len) {
        if (str.charAt(i) == sep) {
          if (match || preserveAllTokens) {
            lastMatch = true;
            if (sizePlus1++ == max) {
              i = len;
              lastMatch = false;
            }
            list.add(str.substring(start, i));
            match = false;
          }
          start = ++i;
          continue;
        }
        lastMatch = false;
        match = true;
        i++;
      }
    } else {
      // standard case
      while (i < len) {
        if (separatorChars.indexOf(str.charAt(i)) >= 0) {
          if (match || preserveAllTokens) {
            lastMatch = true;
            if (sizePlus1++ == max) {
              i = len;
              lastMatch = false;
            }
            list.add(str.substring(start, i));
            match = false;
          }
          start = ++i;
          continue;
        }
        lastMatch = false;
        match = true;
        i++;
      }
    }
    if (match || (preserveAllTokens && lastMatch)) {
      list.add(str.substring(start, i));
    }
    return (String[]) list.toArray(new String[list.size()]);
  }

  // Joining
  //-----------------------------------------------------------------------

  /**
   * <p>Returns either the passed in String,
   * or if the String is <code>null</code>, an empty String ("").</p>
   *
   * <pre>
   * StringUtils.defaultString(null)  = ""
   * StringUtils.defaultString("")    = ""
   * StringUtils.defaultString("bat") = "bat"
   * </pre>
   *
   * @see String#valueOf(Object)
   * @param str  the String to check, may be null
   * @return the passed in String, or the empty String if it
   *  was <code>null</code>
   */
  public static String defaultString(String str) {
    return str == null ? "" : str;
  }

  /**
   * An empty immutable <code>String</code> array.
   */
  public static final String[] EMPTY_STRING_ARRAY = new String[0];

  /**
   * get a jar file from a sample class
   * @param sampleClass the class for which the jar is looked up
   * @return the jar file
   */
  public static File jarFile(Class sampleClass) {
    try {
      CodeSource codeSource = sampleClass.getProtectionDomain().getCodeSource();
      if (codeSource != null && codeSource.getLocation() != null) {
        String fileName = URLDecoder.decode(codeSource.getLocation().getFile(), "UTF-8");
        return new File(fileName);
      }
      String resourcePath = sampleClass.getName();
      resourcePath = resourcePath.replace('.', '/') + ".class";
      URL url = computeUrl(resourcePath, true);
      String urlPath = url.toString();
      
      if (urlPath.startsWith("jar:")) {
        urlPath = urlPath.substring(4);
      }
      if (urlPath.startsWith("file:")) {
        urlPath = urlPath.substring(5);
      }
      urlPath = prefixOrSuffix(urlPath, "!", true); 
  
      urlPath = URLDecoder.decode(urlPath, "UTF-8");
  
      File file = new File(urlPath);
      if (urlPath.endsWith(".jar") && file.exists() && file.isFile()) {
        return file;
      }
    } catch (Exception e) {
    }
    return null;
  }

  /**
   * strip the last slash (/ or \) from a string if it exists
   * 
   * @param input A string potentially ending in '\' or '/'
   * 
   * @return input without the last / or \
   */
  public static String stripLastSlashIfExists(String input) {
    if ((input == null) || (input.length() == 0)) {
      return null;
    }

    char lastChar = input.charAt(input.length() - 1);

    if ((lastChar == '\\') || (lastChar == '/')) {
      return input.substring(0, input.length() - 1);
    }

    return input;
  }
}
