
/**
 * The OWASP CSRFGuard Project, BSD License
 * Eric Sheridan (eric@infraredsecurity.com), Copyright (c) 2011 
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *    3. Neither the name of OWASP nor the names of its contributors may be used
 *       to endorse or promote products derived from this software without specific
 *       prior written permission.
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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.PushbackInputStream;
import java.io.Reader;
import java.io.Serializable;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.lang.annotation.Annotation;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.math.BigDecimal;
import java.net.InetAddress;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.CodeSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.text.DateFormat;
import java.text.DecimalFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.regex.Matcher;
import java.util.regex.Pattern;



/**
 * utility methods for grouper.
 * @author mchyzer
 *
 */
@SuppressWarnings({ "serial", "unchecked" })
public class ConfigPropertiesCascadeCommonUtils  {

  /** override map for properties in thread local to be used in a web server or the like */
  private static ThreadLocal<Map<String, Map<String, String>>> propertiesThreadLocalOverrideMap = new ThreadLocal<Map<String, Map<String, String>>>();

  /**
   * return the arg after the argBefore, or null if not there, or exception
   * if argBefore is not found
   * @param args array of arguments
   * @param argBefore the argument immediately preceeding the desired value
   * @return the arg that appears just after argBefore
   */
  public static String argAfter(String[] args, String argBefore) {
    if (length(args) <= 1) {
      return null;
    }
    int argBeforeIndex = -1;
    for (int i=0;i<args.length;i++) {
      if (equals(args[i], argBefore)) {
        argBeforeIndex = i;
        break;
      }
    }
    if (argBeforeIndex == -1) {
      throw new RuntimeException("Cant find arg before");
    }
    if (argBeforeIndex < args.length - 1) {
      return args[argBeforeIndex + 1];
    }
    return null;
  }
  
  /**
   * append and maybe put a separator in there
   * @param result The containier for the modified StringBuilder
   * @param separatorIfResultNotEmpty the separator string to append when adding to a non-blank result
   * @param stringToAppend the string to append
   */
  public static void append(StringBuilder result, 
      String separatorIfResultNotEmpty, String stringToAppend) {
    if (result.length() != 0) {
      result.append(separatorIfResultNotEmpty);
    }
    result.append(stringToAppend);
  }
  
  /**
   * 
   */
  public static final String LOG_ERROR = "Error trying to make parent dirs for logger or logging first statement, check to make " +
                "sure you have proper file permissions, and that your servlet container is giving " +
                "your app rights to access the log directory (e.g. for tomcat set TOMCAT5_SECURITY=no), g" +
                "oogle it for more info";

  /**
   * The number of bytes in a kilobyte.
   */
  public static final long ONE_KB = 1024;

  /**
   * The number of bytes in a megabyte.
   */
  public static final long ONE_MB = ONE_KB * ONE_KB;

  /**
   * The number of bytes in a gigabyte.
   */
  public static final long ONE_GB = ONE_KB * ONE_MB;

  /**
   * Returns a human-readable version of the file size (original is in
   * bytes).
   *
   * @param size The number of bytes.
   * @return     A human-readable display value (includes units).
   */

  //TODO: need for I18N?
  public static String byteCountToDisplaySize(long size) {
    String displaySize;

    if (size / ONE_GB > 0) {
      displaySize = String.valueOf(size / ONE_GB) + " GB";
    } else if (size / ONE_MB > 0) {
      displaySize = String.valueOf(size / ONE_MB) + " MB";
    } else if (size / ONE_KB > 0) {
      displaySize = String.valueOf(size / ONE_KB) + " KB";
    } else {
      displaySize = String.valueOf(size) + " bytes";
    }

    return displaySize;
  }
  /**
   * see if options have a specific option by int bits
   * @param options The options integer that holds option flag bits
   * @param option  The option flag bit to check
   * @return true if the option flag is set in the options int 
   */
  public static boolean hasOption(int options, int option) {
    return (options & option) > 0;
  }
  
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
   * return the suffix after a char.  If the char doesn't exist, just return the string
   * @param input string
   * @param theChar the marker character such as "."
   * @return Suffix of string after the last index of the specified character
   */
  public static String suffixAfterChar(String input, char theChar) {
    if (input == null) {
      return null;
    }
    //get the real type off the end
    int lastIndex = input.lastIndexOf(theChar);
    if (lastIndex > -1) {
      input = input.substring(lastIndex + 1, input.length());
    }
    return input;
  }

  /**
   * get the oracle underscore name e.g. javaNameHere &rarr; JAVA_NAME_HERE
   *
   * @param javaName
   *          the java convention name, in camelCase
   *
   * @return the oracle underscore name based on the java name
   */
  public static String oracleStandardNameFromJava(String javaName) {
  
    StringBuilder result = new StringBuilder();
  
    if ((javaName == null) || (0 == "".compareTo(javaName))) {
      return javaName;
    }
  
    //if package is specified, only look at class name
    javaName = suffixAfterChar(javaName, '.');
  
    //don't check the first char
    result.append(javaName.charAt(0));
  
    char currChar;
  
    boolean previousCap = false;
    
    //loop through the string, looking for uppercase
    for (int i = 1; i < javaName.length(); i++) {
      currChar = javaName.charAt(i);
  
      //if uppcase append an underscore
      if (!previousCap && (currChar >= 'A') && (currChar <= 'Z')) {
        result.append("_");
      }
  
      result.append(currChar);
      if ((currChar >= 'A') && (currChar <= 'Z')) {
        previousCap = true;
      } else {
        previousCap = false;
      }
    }
  
    //this is in upper-case
    return result.toString().toUpperCase();
  }

  
  /**
   * see if two maps are the equivalent (based on number of entries, 
   * and the equals() method of the keys and values)
   *
   * @param <K> key type
   * @param <V> value type
   * @param first the first map to compare
   * @param second the second map to compare
   * @return true if equal
   */
  public static <K,V> boolean mapEquals(Map<K,V> first, Map<K,V> second) {
    Set<K> keysMismatch = new HashSet<K>();
    mapDifferences(first, second, keysMismatch, null);
    //if any keys mismatch, then not equal
    return keysMismatch.size() == 0;
    
  }
  
  /**
   * empty map
   */
  private static final Map EMPTY_MAP = Collections.unmodifiableMap(new HashMap());
  
  /**
   * see if two maps are the equivalent (based on number of entries, 
   * and the equals() method of the keys and values)
   * @param <K> key type
   * @param <V> value type
   * @param first map to check diffs
   * @param second map to check diffs
   * @param differences set of keys (with prefix) of the diffs
   * @param prefix for the entries in the diffs (e.g. "attribute__")
   */
  @SuppressWarnings("unchecked")
  public static <K,V> void mapDifferences(Map<K,V> first, Map<K,V> second, Set<K> differences, String prefix) {
    if (first == second) {
      return;
    }
    //put the collections in new collections so we can remove and keep track
    if (first == null) {
      first = EMPTY_MAP;
    }
    if (second == null) {
      second = EMPTY_MAP;
    } else {
      //make linked so the results are ordered
      second = new LinkedHashMap<K,V>(second);
    }
    int firstSize = first == null ? 0 : first.size();
    int secondSize = second == null ? 0 : second.size();
    //if both empty then all good
    if (firstSize == 0 && secondSize == 0) {
      return;
    }
   
    for (K key : first.keySet()) {

      if (second.containsKey(key)) {
        V firstValue = first.get(key);
        V secondValue = second.get(key);
        //keep track by removing from second
        second.remove(key);
        if (equals(firstValue, secondValue)) {
          continue;
        }
      }
      differences.add(isNotBlank(prefix) ? (K)(prefix + key) : key);
    }
    //add the ones left over in the second map which are not in the first map
    for (K key : second.keySet()) {
      differences.add(isNotBlank(prefix) ? (K)(prefix + key) : key);
    }
  }
  
  /**
   * Sleep for the specified number of milliseconds and throw RuntimeExeption if interrupted.
   *
   * @param millis Number of milliseconds to sleep
   * @see Thread#sleep
   */
  public static void sleep(long millis) {
    try {
      Thread.sleep(millis);
    } catch (InterruptedException ie) {
      throw new RuntimeException(ie);
    }
  }
  
  /**
   * If we can, inject this into the exception, else return false
   * @param t The Throwable to inject
   * @param message The message to append to the throwable's message
   * @return true if success, false if not
   */
  public static boolean injectInException(Throwable t, String message) {
    
    String throwableFieldName = "detailMessage";

    try {
      String currentValue = t.getMessage();
      if (!isBlank(currentValue)) {
        currentValue += ",\n" + message;
      } else {
        currentValue = message;
      }
      assignField(t, throwableFieldName, currentValue);
      return true;
    } catch (Throwable t2) {
      //dont worry about what the problem is, return false so the caller can log
      return false;
    }
    
  }
  
  /**
   * get a unique string identifier based on the current time,
   * this is not globally unique, just unique for as long as this
   * server is running...
   * 
   * @return String
   */
  public static String uniqueId() {
    //this needs to be threadsafe since we are using a static field
    synchronized (ConfigPropertiesCascadeCommonUtils.class) {
      lastId = incrementStringInt(lastId);
    }

    return String.valueOf(lastId);
  }

  /**
   * get a file name from a resource name
   * 
   * @param resourceName
   *          is the classpath location
   * 
   * @return the file path on the system
   */
  public static File fileFromResourceName(String resourceName) {
    
    URL url = computeUrl(resourceName, true);

    if (url == null) {
      return null;
    }

    try {
      String fileName = URLDecoder.decode(url.getFile(), "UTF-8");
  
      File configFile = new File(fileName);

      return configFile;
    } catch (UnsupportedEncodingException uee) {
      throw new RuntimeException(uee);
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
   * make sure a array is non null.  If null, then return an empty array.
   * Note: this will probably not work for primitive arrays (e.g. int[])
   * @param <T> template type
   * @param array the array to check
   * @param theClass to make array from
   * @return the list or empty list if null
   */
  @SuppressWarnings("unchecked")
  public static <T> T[] nonNull(T[] array, Class<?> theClass) {
    return array == null ? ((T[])Array.newInstance(theClass, 0)) : array;
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
   * get the extension from name.  if name is a:b:c, name is c
   * @param name a name, potentially containing colon separators such as "a:b:c"
   * @return the extension a.k.a. part of the name after the last colon character
   */
  public static String extensionFromName(String name) {
    if (isBlank(name)) {
      return name;
    }
    int lastColonIndex = name.lastIndexOf(':');
    if (lastColonIndex == -1) {
      return name;
    }
    String extension = name.substring(lastColonIndex+1);
    return extension;
  }
  
  /**
   * Returns the class object for the given name.
   * @param origClassName fully qualified class name
   * @return the class
   */
  public static Class forName(String origClassName) {
        
    try {
      return Class.forName(origClassName);
    } catch (Throwable t) {
      throw new RuntimeException("Problem loading class: " + origClassName, t);
    }
    
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
   * get the parent stem name from name.  if already a root stem
   * then just return null.  e.g. if the name is a:b:c then
   * the return value is a:b
   * @param name a colon-delimited name such as "a:b:c"
   * @return the parent stem name or null if none
   */
  public static String parentStemNameFromName(String name) {
    int lastColonIndex = name.lastIndexOf(':');
    if (lastColonIndex == -1) {
      return null;
    }
    String parentStemName = name.substring(0,lastColonIndex);
    return parentStemName;

  }
  
  /**
   * return the string or the other if the first is blank
   * @param string The string
   * @param defaultStringIfBlank The string used when the first parameter is blank
   * @return the string or the default one if the string was blank
   */
  public static String defaultIfBlank(String string, String defaultStringIfBlank) {
    return isBlank(string) ? defaultStringIfBlank : string;
  }
  
  /**
   * genericized method to see if first is null, if so then return second, else first.
   * @param <T> template type
   * @param theValue first input
   * @param defaultIfTheValueIsNull second input
   * @return the first if not null, second if no
   */
  public static <T> T defaultIfNull(T theValue, T defaultIfTheValueIsNull) {
    return theValue != null ? theValue : defaultIfTheValueIsNull;
  }
  
  /**
   * add each element of listToAdd if it is not already in list
   * @param <T> template type
   * @param list to add to
   * @param listToAdd each element will be added to list, or null if none
   */
  public static <T> void addIfNotThere(Collection<T> list, Collection<T> listToAdd) {
    //maybe nothing to do
    if (listToAdd == null) {
      return;
    }
    for (T t : listToAdd) {
      if (!list.contains(t)) {
        list.add(t);
      }
    }
  }

  
  /**
   * print out various types of objects
   * 
   * @param object the object to convert into a human-readable string
   * @param maxChars is where it should stop when figuring out object.  note, result might be longer than max...
   * need to abbreviate when back
   * @param result is where to append to
   */
  @SuppressWarnings("unchecked")
  private static void toStringForLogHelper(Object object, int maxChars, StringBuilder result) {
    
    try {
      if (object == null) {
        result.append("null");
      } else if (object.getClass().isArray()) {
        // handle arrays
        int length = Array.getLength(object);
        if (length == 0) {
          result.append("Empty array");
        } else {
          result.append("Array size: ").append(length).append(": ");
          for (int i = 0; i < length; i++) {
            result.append("[").append(i).append("]: ").append(
                Array.get(object, i)).append("\n");
            if (maxChars != -1 && result.length() > maxChars) {
              return;
            }
          }
        }
      } else if (object instanceof Collection) {
        //give size and type if collection
        Collection<Object> collection = (Collection<Object>) object;
        int collectionSize = collection.size();
        if (collectionSize == 0) {
          result.append("Empty ").append(object.getClass().getSimpleName());
        } else {
          result.append(object.getClass().getSimpleName()).append(" size: ").append(collectionSize).append(": ");
          int i=0;
          for (Object collectionObject : collection) {
            result.append("[").append(i).append("]: ").append(
                collectionObject).append("\n");
            if (maxChars != -1 && result.length() > maxChars) {
              return;
            }
            i++;
          }
        }
      } else {
        result.append(object.toString());
      }
    } catch (Exception e) {
      result.append("<<exception>> ").append(object.getClass()).append(":\n")
        .append(getFullStackTrace(e)).append("\n");
    }
  }

  /**
   * convert a set to a string (comma separate)
   * @param set the set to convert into a human-readable string
   * @return the String
   */
  public static String setToString(Set set) {
    if (set == null) {
      return "null";
    }
    if (set.size() == 0) {
      return "empty";
    }
    StringBuilder result = new StringBuilder();
    boolean first = true;
    for (Object object : set) {
      if (!first) {
        result.append(", ");
      }
      first = false;
      result.append(object);
    }
    return result.toString();
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
   * print out various types of objects
   * 
   * @param object the object to convert to a human-readable string
   * @return the string value
   */
  public static String toStringForLog(Object object) {
    StringBuilder result = new StringBuilder();
    toStringForLogHelper(object, -1, result);
    return result.toString();
  }

  /**
   * print out various types of objects
   * 
   * @param object the object to convert to a human-readable string
   * @param maxChars is the max chars that should be returned (abbreviate if longer), or -1 for any amount
   * @return the string value
   */
  public static String toStringForLog(Object object, int maxChars) {
    StringBuilder result = new StringBuilder();
    toStringForLogHelper(object, -1, result);
    String resultString = result.toString();
    if (maxChars != -1) {
      return abbreviate(resultString, maxChars);
    }
    return resultString;
  }

  /**
   * If batching this is the number of batches
   * @param count is size of set
   * @param batchSize the batch size
   * @return the number of batches
   */
  public static int batchNumberOfBatches(int count, int batchSize) {
    int batches = 1 + ((count - 1) / batchSize);
    return batches;

  }

  /**
   * If batching this is the number of batches
   * @param collection the collection
   * @param batchSize the batch size
   * @return the number of batches
   */
  public static int batchNumberOfBatches(Collection<?> collection, int batchSize) {
    int arrraySize = length(collection);
    return batchNumberOfBatches(arrraySize, batchSize);

  }

  /**
   * retrieve a batch by 0 index. Will return an array of size batchSize or
   * the remainder. the array will be full of elements. Note, this requires an
   * ordered input (so use linkedhashset not hashset if doing sets)
   * @param <T> template type
   * @param collection the collection
   * @param batchSize the batch size
   * @param batchIndex the batch index
   * @return the list
   *         This never returns null, only empty list
   */
  @SuppressWarnings("unchecked")
  public static <T> List<T> batchList(Collection<T> collection, int batchSize,
      int batchIndex) {

    int numberOfBatches = batchNumberOfBatches(collection, batchSize);
    int arraySize = length(collection);

    // short circuit
    if (arraySize == 0) {
      return new ArrayList<T>();
    }

    List<T> theBatchObjects = new ArrayList<T>();

    // lets get the type of the first element if possible
//    Object first = get(arrayOrCollection, 0);
//
//    Class theType = first == null ? Object.class : first.getClass();

    // if last batch
    if (batchIndex == numberOfBatches - 1) {

      // needs to work to 1-n
      //int thisBatchSize = 1 + ((arraySize - 1) % batchSize);

      int collectionIndex = 0;
      for (T t : collection) {
        if (collectionIndex++ < batchIndex * batchSize) {
          continue;
        }
        //just copy the rest
        //if (collectionIndex >= (batchIndex * batchSize) + arraySize) {
        //  break;
        //}
        //we are in the copy mode
        theBatchObjects.add(t);
      }

    } else {
      // if non-last batch
      //int newIndex = 0;
      int collectionIndex = 0;
      for (T t : collection) {
        if (collectionIndex < batchIndex * batchSize) {
          collectionIndex++;
          continue;
        }
        //done with batch
        if (collectionIndex >= (batchIndex + 1) * batchSize) {
          break;
        }
        theBatchObjects.add(t);
        collectionIndex++;
      }
    }
    return theBatchObjects;
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
   * escape url chars (e.g. a # is %23)
   * @param string input
   * @return the encoded string
   */
  public static String escapeUrlEncode(String string) {
    String result = null;
    try {
      result = URLEncoder.encode(string, "UTF-8");
    } catch (UnsupportedEncodingException ex) {
      throw new RuntimeException("UTF-8 not supported", ex);
    }
    return result;
  }
  
  /**
   * unescape url chars (e.g. a space is %20)
   * @param string input
   * @return the encoded string
   */
  public static String escapeUrlDecode(String string) {
    String result = null;
    try {
      result = URLDecoder.decode(string, "UTF-8");
    } catch (UnsupportedEncodingException ex) {
      throw new RuntimeException("UTF-8 not supported", ex);
    }
    return result;
  }

  /**
   * make sure a list is non null.  If null, then return an empty list
   * @param <T> template type
   * @param list the list, or null
   * @return the list or empty list if null
   */
  public static <T> List<T> nonNull(List<T> list) {
    return list == null ? new ArrayList<T>() : list;
  }
  
  /**
   * make sure a list is non null.  If null, then return an empty set
   * @param <T> template type
   * @param set the set, or null
   * @return the set or empty set if null
   */
  public static <T> Set<T> nonNull(Set<T> set) {
    return set == null ? new HashSet<T>() : set;
  }
  
  /**
   * make sure it is non null, if null, then give new map
   * 
   * @param <K> key of map
   * @param <V> value of map
   * @param map is map
   * @return set non null
   */
  public static <K,V> Map<K,V> nonNull(Map<K,V> map) {
    return map == null ? new HashMap<K,V>() : map;
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
   * convert classes to a list
   * @param classes The classes to be returned as a List
   * @return list of classes
   */
  public static List<Class<?>> toListClasses(Class<?>... classes) {
    return toList(classes);
  }
  

  
  /**
   * return a set of objects from varargs.
   * 
   * @param <T> template type of the objects
   * @param objects The objects to be returned as a Set
   * @return the set
   */
  public static <T> Set<T> toSet(T... objects) {

    Set<T> result = new LinkedHashSet<T>();
    for (T object : objects) {
      result.add(object);
    }
    return result;
  }

  /**
   * cache separator
   */
  private static final String CACHE_SEPARATOR = "__";

  /**
   * string format of dates
   */
  public static final String DATE_FORMAT = "yyyyMMdd";

  /**
   * format including minutes and seconds: yyyy/MM/dd HH:mm:ss
   */
  public static final String DATE_MINUTES_SECONDS_FORMAT = "yyyy/MM/dd HH:mm:ss";

  /**
   * format including minutes and seconds: yyyyMMdd HH:mm:ss
   */
  public static final String DATE_MINUTES_SECONDS_NO_SLASH_FORMAT = "yyyyMMdd HH:mm:ss";

  /**
   * format on screen of config for milestone: yyyy/MM/dd HH:mm:ss.SSS
   */
  public static final String TIMESTAMP_FORMAT = "yyyy/MM/dd HH:mm:ss.SSS";

  /**
   * format on screen of config for milestone: yyyyMMdd HH:mm:ss.SSS
   */
  public static final String TIMESTAMP_NO_SLASH_FORMAT = "yyyyMMdd HH:mm:ss.SSS";

  /**
   * date format, make sure to synchronize
   */
  final static SimpleDateFormat dateFormat = new SimpleDateFormat(DATE_FORMAT);

  /**
   * synchronize code that uses this standard formatter for dates with minutes and seconds
   */
  final static SimpleDateFormat dateMinutesSecondsFormat = new SimpleDateFormat(
      DATE_MINUTES_SECONDS_FORMAT);

  /**
   * synchronize code that uses this standard formatter for dates with minutes and seconds
   */
  final static SimpleDateFormat dateMinutesSecondsNoSlashFormat = new SimpleDateFormat(
      DATE_MINUTES_SECONDS_NO_SLASH_FORMAT);

  /**
   * <pre> format: yyyy/MM/dd HH:mm:ss.SSS synchronize code that uses this standard formatter for timestamps </pre>
   */
  final static SimpleDateFormat timestampFormat = new SimpleDateFormat(TIMESTAMP_FORMAT);

  /**
   * synchronize code that uses this standard formatter for timestamps
   */
  final static SimpleDateFormat timestampNoSlashFormat = new SimpleDateFormat(
      TIMESTAMP_NO_SLASH_FORMAT);

  /**
   * If false, throw an assertException, and give a reason
   * 
   * @param isTrue when false, throw a RuntimeException.  When true, do nothing.
   * @param reason the message used for the exception
   */
  public static void assertion(boolean isTrue, String reason) {
    if (!isTrue) {
      throw new RuntimeException(reason);
    }

  }

  /**
   * use the field cache, expire every day (just to be sure no leaks)
   */
  private static ExpirableCache<String, Set<Field>> fieldSetCache = null;
  
  /**
   * lazy load
   * @return field set cache
   */
  private static ExpirableCache<String, Set<Field>> fieldSetCache() {
    if (fieldSetCache == null) {
      fieldSetCache = new ExpirableCache<String, Set<Field>>(60*24);
    }
    return fieldSetCache;
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
   * use the field cache, expire every day (just to be sure no leaks) 
   */
  private static ExpirableCache<String, Set<Method>> getterSetCache = null;
    

  /**
   * lazy load
   * @return getter cache
   */
  private static ExpirableCache<String, Set<Method>> getterSetCache() {
    if (getterSetCache == null) {
      getterSetCache = new ExpirableCache<String, Set<Method>>(60*24);
    }
    return getterSetCache;
  }
  
    

  /**
   * use the field cache, expire every day (just to be sure no leaks) 
   */
  private static ExpirableCache<String, Set<Method>> setterSetCache = null;
    

  /**
   * lazy load
   * @return setter cache
   */
  private static ExpirableCache<String, Set<Method>> setterSetCache() {
    if (setterSetCache == null) {
      setterSetCache = new ExpirableCache<String, Set<Method>>(60*24);
    }
    return setterSetCache;
  }
  
  
  /**
   * Field lastId.
   */
  private static char[] lastId = convertLongToStringSmall(new Date().getTime())
      .toCharArray();

  /**
   * cache the properties read from resource 
   */
  private static Map<String, Properties> resourcePropertiesCache = new HashMap<String, Properties>();

  /**
   * assign data to a field
   * 
   * @param theClass
   *            the class which has the method
   * @param invokeOn
   *            to call on or null for static
   * @param fieldName
   *            method name to call
   * @param dataToAssign
   *            data
   * @param callOnSupers
   *            if static and method not exists, try on supers
   * @param overrideSecurity
   *            true to call on protected or private etc methods
   * @param typeCast
   *            true if we should typecast
   * @param annotationWithValueOverride
   *            annotation with value of override
   */
  public static void assignField(Class theClass, Object invokeOn,
      String fieldName, Object dataToAssign, boolean callOnSupers,
      boolean overrideSecurity, boolean typeCast,
      Class<? extends Annotation> annotationWithValueOverride) {
    if (theClass == null && invokeOn != null) {
      theClass = invokeOn.getClass();
    }
    Field field = field(theClass, fieldName, callOnSupers, true);
    assignField(field, invokeOn, dataToAssign, overrideSecurity, typeCast,
        annotationWithValueOverride);
  }

  /**
   * assign data to a field. Will find the field in superclasses, will
   * typecast, and will override security (private, protected, etc)
   * 
   * @param theClass
   *            the class which has the method
   * @param invokeOn
   *            to call on or null for static
   * @param fieldName
   *            method name to call
   * @param dataToAssign
   *            data
   * @param annotationWithValueOverride
   *            annotation with value of override
   */
  public static void assignField(Class theClass, Object invokeOn,
      String fieldName, Object dataToAssign,
      Class<? extends Annotation> annotationWithValueOverride) {
    assignField(theClass, invokeOn, fieldName, dataToAssign, true, true,
        true, annotationWithValueOverride);
  }

  /**
   * assign data to a field
   * 
   * @param field
   *            is the field to assign to
   * @param invokeOn
   *            to call on or null for static
   * @param dataToAssign
   *            data
   * @param overrideSecurity
   *            true to call on protected or private etc methods
   * @param typeCast
   *            true if we should typecast
   */
  @SuppressWarnings("unchecked")
  public static void assignField(Field field, Object invokeOn,
      Object dataToAssign, boolean overrideSecurity, boolean typeCast) {

    try {
      Class fieldType = field.getType();
      // typecast
      if (typeCast) {
        dataToAssign = 
                 typeCast(dataToAssign, fieldType,
                 true, true);
      }
      if (overrideSecurity) {
        field.setAccessible(true);
      }
      field.set(invokeOn, dataToAssign);
    } catch (Exception e) {
      throw new RuntimeException("Cant assign reflection field: "
          + (field == null ? null : field.getName()) + ", on: "
          + className(invokeOn) + ", with args: "
          + classNameCollection(dataToAssign), e);
    }
  }

  /**
   * null safe iterator getter if the type if collection
   * 
   * @param collection the collection
   * @return the iterator
   */
  public static Iterator iterator(Object collection) {
    if (collection == null) {
      return null;
    }
    // array list doesnt need an iterator
    if (collection instanceof Collection
        && !(collection instanceof ArrayList)) {
      return ((Collection) collection).iterator();
    }
    return null;
  }

  /**
   * Null safe array length or map
   * 
   * @param arrayOrCollection  The array, Collection, or Map for which to find the length or size.
   * @return the length of the array (0 for null)
   */
  public static int length(Object arrayOrCollection) {
    if (arrayOrCollection == null) {
      return 0;
    }
    if (arrayOrCollection.getClass().isArray()) {
      return Array.getLength(arrayOrCollection);
    }
    if (arrayOrCollection instanceof Collection) {
      return ((Collection) arrayOrCollection).size();
    }
    if (arrayOrCollection instanceof Map) {
      return ((Map) arrayOrCollection).size();
    }
    // simple non array non collection object
    return 1;
  }

  /**
   * If array, get the element based on index, if Collection, get it based on
   * iterator.
   * 
   * @param arrayOrCollection The array, ArrayList, or Collection from which to get the specified element
   * @param iterator          for Collections, this iterator is used to find the next object
   * @param index             The object at this specified index, or when 0, the arrayOrCollection itself
   * @return the object
   */
  public static Object next(Object arrayOrCollection, Iterator iterator,
      int index) {
    if (arrayOrCollection.getClass().isArray()) {
      return Array.get(arrayOrCollection, index);
    }
    if (arrayOrCollection instanceof ArrayList) {
      return ((ArrayList) arrayOrCollection).get(index);
    }
    if (arrayOrCollection instanceof Collection) {
      return iterator.next();
    }
    // simple object
    if (0 == index) {
      return arrayOrCollection;
    }
    throw new RuntimeException("Invalid class type: "
        + arrayOrCollection.getClass().getName());
  }

  /**
   * Remove the iterator or index
   * 
   * @param arrayOrCollection The Array, List, or Collection from which to remove the object referenced by the iterator or index number
   * @param index             Index of the item that should be removed. 
   * @return the object list or new array
   */
  public static Object remove(Object arrayOrCollection, 
      int index) {
    return remove(arrayOrCollection, null, index);
  }
  
  /**
   * Remove the iterator or index
   * 
   * @param arrayOrCollection The Array, List, or Collection from which to remove the object referenced by the iterator or index number
   * @param iterator          Iterator for the collection used to remove the object. Takes precedence over index parameter when non-null.
   * @param index             Index of the item that should be removed. 
   * @return the object list or new array
   */
  public static Object remove(Object arrayOrCollection, Iterator iterator,
      int index) {
    
    //if there's an iterator, just use that
    if (iterator != null) {
      iterator.remove();
      return arrayOrCollection;
    }
    if (arrayOrCollection.getClass().isArray()) {
      int newLength = Array.getLength(arrayOrCollection) - 1;
      Object newArray = Array.newInstance(arrayOrCollection.getClass().getComponentType(), newLength);
      if (newLength == 0) {
        return newArray;
      }
      if (index > 0) {
        System.arraycopy(arrayOrCollection, 0, newArray, 0, index);
      }
      if (index < newLength) {
        System.arraycopy(arrayOrCollection, index+1, newArray, index, newLength - index);
      }
      return newArray;
    }
    if (arrayOrCollection instanceof List) {
      ((List)arrayOrCollection).remove(index);
      return arrayOrCollection;
    } else if (arrayOrCollection instanceof Collection) {
      //this should work unless there are duplicates or something weird
      ((Collection)arrayOrCollection).remove(get(arrayOrCollection, index));
      return arrayOrCollection;
    }
    throw new RuntimeException("Invalid class type: "
        + arrayOrCollection.getClass().getName());
  }

  /**
   * print the simple names of a list of classes
   * @param object  An array of objects
   * @return the simple names for the objects in the array
   * @see Class#getSimpleName()
   */
  public static String classesString(Object object) {
    StringBuilder result = new StringBuilder();
    if (object.getClass().isArray()) {
      int length = Array.getLength(object);
      for (int i=0;i<length;i++) {
        result.append(((Class)object).getSimpleName());
        if (i < length-1) {
          result.append(", ");
        }
      }
      return result.toString();
    }
    
    throw new RuntimeException("Not implemented: " + className(object));
  }
  
  /**
   * null safe classname method, max out at 20
   * 
   * @param object  The object over which to iterate, producing a comma separated list of class names
   * @return the classname
   */
  public static String classNameCollection(Object object) {
    if (object == null) {
      return null;
    }
    StringBuffer result = new StringBuffer();
    
    Iterator iterator = iterator(object);
    int length = length(object);
    for (int i = 0; i < length && i < 20; i++) {
      result.append(className(next(object, iterator, i)));
      if (i != length - 1) {
        result.append(", ");
      }
    }
    return result.toString();
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
   * assign data to a field
   * 
   * @param field
   *            is the field to assign to
   * @param invokeOn
   *            to call on or null for static
   * @param dataToAssign
   *            data
   * @param overrideSecurity
   *            true to call on protected or private etc methods
   * @param typeCast
   *            true if we should typecast
   * @param annotationWithValueOverride
   *            annotation with value of override, or null if none
   */
  @SuppressWarnings("unchecked")
  public static void assignField(Field field, Object invokeOn,
      Object dataToAssign, boolean overrideSecurity, boolean typeCast,
      Class<? extends Annotation> annotationWithValueOverride) {

    if (annotationWithValueOverride != null) {
      // see if in annotation
      Annotation annotation = field
          .getAnnotation(annotationWithValueOverride);
      if (annotation != null) {
        
         // type of the value, or String if not specific Class
          // typeOfAnnotationValue = typeCast ? field.getType() :
          // String.class; dataToAssign =
          // AnnotationUtils.retrieveAnnotationValue(
          // typeOfAnnotationValue, annotation, "value");
        
        throw new RuntimeException("Not supported");
      }
    }
    assignField(field, invokeOn, dataToAssign, overrideSecurity, typeCast);
  }

  /**
   * assign data to a field. Will find the field in superclasses, will
   * typecast, and will override security (private, protected, etc)
   * 
   * @param invokeOn
   *            to call on or null for static
   * @param fieldName
   *            method name to call
   * @param dataToAssign
   *            data
   */
  public static void assignField(Object invokeOn, String fieldName,
      Object dataToAssign) {
    assignField(null, invokeOn, fieldName, dataToAssign, true, true, true,
        null);
  }

  /**
   * get a field object for a class, potentially in superclasses
   * 
   * @param theClass
   *            The class potentially containing the field 
   * @param fieldName
   *            The name of the desired class field
   * @param callOnSupers
   *            true if superclasses should be looked in for the field
   * @param throwExceptionIfNotFound
   *            will throw runtime exception if not found
   * @return the field object or null if not found (or exception if param is
   *         set)
   * @see Class#getDeclaredField(String)
   */
  public static Field field(Class theClass, String fieldName,
      boolean callOnSupers, boolean throwExceptionIfNotFound) {
    try {
      Field field = theClass.getDeclaredField(fieldName);
      // found it
      return field;
    } catch (NoSuchFieldException e) {
      // if method not found
      // if traversing up, and not Object, and not instance method
      if (callOnSupers && !theClass.equals(Object.class)) {
        return field(theClass.getSuperclass(), fieldName, callOnSupers,
            throwExceptionIfNotFound);
      }
    }
    // maybe throw an exception
    if (throwExceptionIfNotFound) {
      throw new RuntimeException("Cant find field: " + fieldName
          + ", in: " + theClass + ", callOnSupers: " + callOnSupers);
    }
    return null;
  }

  /**
   * return a set of Strings for a class and type. This is not for any
   * supertypes, only for the type at hand. includes final fields
   * 
   * @param theClass the class to look for fields in
   * @param fieldType
   *            or null for all
   * @param includeStaticFields when true, include static fields
   * @return the set of strings, or the empty Set if none
   */
  @SuppressWarnings("unchecked")
  public static Set<String> fieldNames(Class theClass, Class fieldType,
      boolean includeStaticFields) {
    return fieldNamesHelper(theClass, theClass, fieldType, true, true,
        includeStaticFields, null, true);
  }

  /**
   * get all field names from a class, including superclasses (if specified)
   * 
   * @param theClass
   *            to look for fields in
   * @param superclassToStopAt
   *            to go up to or null to go up to Object
   * @param fieldType
   *            is the type of the field to get
   * @param includeSuperclassToStopAt
   *            if we should include the superclass
   * @param includeStaticFields
   *            if include static fields
   * @param includeFinalFields
   *            if final fields should be included
   * @return the set of field names or empty set if none
   */
  public static Set<String> fieldNames(Class theClass,
      Class superclassToStopAt, Class<?> fieldType,
      boolean includeSuperclassToStopAt, boolean includeStaticFields,
      boolean includeFinalFields) {
    return fieldNamesHelper(theClass, superclassToStopAt, fieldType,
        includeSuperclassToStopAt, includeStaticFields,
        includeFinalFields, null, true);

  }

  /**
   * get all field names from a class, including superclasses (if specified).
   * ignore a certain marker annotation
   * 
   * @param theClass
   *            to look for fields in
   * @param superclassToStopAt
   *            to go up to or null to go up to Object
   * @param fieldType
   *            is the type of the field to get
   * @param includeSuperclassToStopAt
   *            if we should include the superclass
   * @param includeStaticFields
   *            if include static fields
   * @param includeFinalFields
   *            if final fields should be included
   * @param markerAnnotationToIngore
   *            if this is not null, then if the field has this annotation,
   *            then do not include in list
   * @return the set of field names
   */
  public static Set<String> fieldNames(Class theClass,
      Class superclassToStopAt, Class<?> fieldType,
      boolean includeSuperclassToStopAt, boolean includeStaticFields,
      boolean includeFinalFields,
      Class<? extends Annotation> markerAnnotationToIngore) {
    return fieldNamesHelper(theClass, superclassToStopAt, fieldType,
        includeSuperclassToStopAt, includeStaticFields,
        includeFinalFields, markerAnnotationToIngore, false);

  }

  /**
   * get all field names from a class, including superclasses (if specified)
   * (up to and including the specified superclass). ignore a certain marker
   * annotation. Dont get static or final field, and get fields of all types
   * 
   * @param theClass
   *            to look for fields in
   * @param superclassToStopAt
   *            to go up to or null to go up to Object
   * @param markerAnnotationToIngore
   *            if this is not null, then if the field has this annotation,
   *            then do not include in list
   * @return the set of field names or empty set if none
   */
  public static Set<String> fieldNames(Class theClass,
      Class superclassToStopAt,
      Class<? extends Annotation> markerAnnotationToIngore) {
    return fieldNamesHelper(theClass, superclassToStopAt, null, true,
        false, false, markerAnnotationToIngore, false);
  }

  /**
   * get all field names from a class, including superclasses (if specified)
   * 
   * @param theClass
   *            to look for fields in
   * @param superclassToStopAt
   *            to go up to or null to go up to Object
   * @param fieldType
   *            is the type of the field to get
   * @param includeSuperclassToStopAt
   *            if we should include the superclass
   * @param includeStaticFields
   *            if include static fields
   * @param includeFinalFields
   *            true to include finals
   * @param markerAnnotation
   *            if this is not null, then if the field has this annotation,
   *            then do not include in list (if includeAnnotation is false)
   * @param includeAnnotation
   *            true if the attribute should be included if annotation is
   *            present, false if exclude
   * @return the set of field names or empty set if none
   */
  @SuppressWarnings("unchecked")
  static Set<String> fieldNamesHelper(Class theClass,
      Class superclassToStopAt, Class<?> fieldType,
      boolean includeSuperclassToStopAt, boolean includeStaticFields,
      boolean includeFinalFields,
      Class<? extends Annotation> markerAnnotation,
      boolean includeAnnotation) {
    Set<Field> fieldSet = fieldsHelper(theClass, superclassToStopAt,
        fieldType, includeSuperclassToStopAt, includeStaticFields,
        includeFinalFields, markerAnnotation, includeAnnotation);
    Set<String> fieldNameSet = new LinkedHashSet<String>();
    for (Field field : fieldSet) {
      fieldNameSet.add(field.getName());
    }
    return fieldNameSet;

  }

  /**
   * get all fields from a class, including superclasses (if specified)
   * 
   * @param theClass
   *            to look for fields in
   * @param superclassToStopAt
   *            to go up to or null to go up to Object
   * @param fieldType
   *            is the type of the field to get
   * @param includeSuperclassToStopAt
   *            if we should include the superclass
   * @param includeStaticFields
   *            if include static fields
   * @param includeFinalFields
   *            if final fields should be included
   * @param markerAnnotation
   *            if this is not null, then if the field has this annotation,
   *            then do not include in list (if includeAnnotation is false)
   * @param includeAnnotation
   *            true if the attribute should be included if annotation is
   *            present, false if exclude
   * @return the set of fields (wont return null)
   */
  @SuppressWarnings("unchecked")
  public static Set<Field> fields(Class theClass, Class superclassToStopAt,
      Class fieldType, boolean includeSuperclassToStopAt,
      boolean includeStaticFields, boolean includeFinalFields,
      Class<? extends Annotation> markerAnnotation,
      boolean includeAnnotation) {
    return fieldsHelper(theClass, superclassToStopAt, fieldType,
        includeSuperclassToStopAt, includeStaticFields,
        includeFinalFields, markerAnnotation, includeAnnotation);
  }

  /**
   * get all fields from a class, including superclasses (if specified) (up to
   * and including the specified superclass). ignore a certain marker
   * annotation, or only include it. Dont get static or final field, and get
   * fields of all types
   * 
   * @param theClass
   *            to look for fields in
   * @param superclassToStopAt
   *            to go up to or null to go up to Object
   * @param markerAnnotation
   *            if this is not null, then if the field has this annotation,
   *            then do not include in list (if includeAnnotation is false)
   * @param includeAnnotation
   *            true if the attribute should be included if annotation is
   *            present, false if exclude
   * @return the set of field names or empty set if none
   */
  @SuppressWarnings("unchecked")
  public static Set<Field> fields(Class theClass, Class superclassToStopAt,
      Class<? extends Annotation> markerAnnotation,
      boolean includeAnnotation) {
    return fieldsHelper(theClass, superclassToStopAt, null, true, false,
        false, markerAnnotation, includeAnnotation);
  }

  /**
   * get all fields from a class, including superclasses (if specified)
   * 
   * @param theClass
   *            to look for fields in
   * @param superclassToStopAt
   *            to go up to or null to go up to Object
   * @param fieldType
   *            is the type of the field to get
   * @param includeSuperclassToStopAt
   *            if we should include the superclass
   * @param includeStaticFields
   *            if include static fields
   * @param includeFinalFields
   *            if final fields should be included
   * @param markerAnnotation
   *            if this is not null, then if the field has this annotation,
   *            then do not include in list (if includeAnnotation is false)
   * @param includeAnnotation
   *            true if the attribute should be included if annotation is
   *            present, false if exclude
   * @return the set of fields (wont return null)
   */
  @SuppressWarnings("unchecked")
  static Set<Field> fieldsHelper(Class theClass, Class superclassToStopAt,
      Class<?> fieldType, boolean includeSuperclassToStopAt,
      boolean includeStaticFields, boolean includeFinalFields,
      Class<? extends Annotation> markerAnnotation,
      boolean includeAnnotation) {
    // MAKE SURE IF ANY MORE PARAMS ARE ADDED, THE CACHE KEY IS CHANGED!

    Set<Field> fieldNameSet = null;
    String cacheKey = theClass + CACHE_SEPARATOR + superclassToStopAt
        + CACHE_SEPARATOR + fieldType + CACHE_SEPARATOR
        + includeSuperclassToStopAt + CACHE_SEPARATOR
        + includeStaticFields + CACHE_SEPARATOR + includeFinalFields
        + CACHE_SEPARATOR + markerAnnotation + CACHE_SEPARATOR
        + includeAnnotation;
    fieldNameSet = fieldSetCache().get(cacheKey);
    if (fieldNameSet != null) {
      return fieldNameSet;
    }

    fieldNameSet = new LinkedHashSet<Field>();
    fieldsHelper(theClass, superclassToStopAt, fieldType,
        includeSuperclassToStopAt, includeStaticFields,
        includeFinalFields, markerAnnotation, fieldNameSet,
        includeAnnotation);

    // add to cache
    fieldSetCache().put(cacheKey, fieldNameSet);

    return fieldNameSet;

  }

  /**
   * compare two objects, compare primitives, Strings, maps of string attributes.
   * if both objects equal each others references, then return empty set.
   * Otherwise if not, then if either is null, return all fields
   *
   * @param first The first object to compare.
   * @param second The second object to compare.
   * @param fieldsToCompare The field names on both objects that should be compared
   * @param mapPrefix is the prefix for maps which are compared (e.g. attribute__)
   * @return the set of fields which are different.  never returns null
   */
  @SuppressWarnings("unchecked")
  public static Set<String> compareObjectFields(Object first, Object second, 
      Set<String> fieldsToCompare, String mapPrefix) {
    
    Set<String> differentFields = new LinkedHashSet<String>();
    
    if (first == second) {
      return differentFields;
    }
    
    //if either null, then all fields are different
    if (first == null || second == null) {
      differentFields.addAll(fieldsToCompare);
    }

    for (String fieldName : fieldsToCompare) {
      try {
        Object firstValue = fieldValue(first, fieldName);
        Object secondValue = fieldValue(second, fieldName);
        
        if (firstValue == secondValue) {
          continue;
        }
        if (firstValue instanceof Map || secondValue instanceof Map) {
          mapDifferences((Map)firstValue, (Map)secondValue, differentFields, mapPrefix);
          continue;
        }
        //compare things...
        //for strings, null is equal to empty
        if (firstValue instanceof String || secondValue instanceof String) {
          if (!equals(defaultString((String)firstValue),
              defaultString((String)secondValue))) {
            differentFields.add(fieldName);
          }
          continue;
        }
        //if one is null, that is not good
        if (firstValue == null || secondValue == null) {
          differentFields.add(fieldName);
          continue;
        }
        //everything (numbers, dates, etc) should work with equals method...
        if (!firstValue.equals(secondValue)) {
          differentFields.add(fieldName);
        }
        
      } catch (RuntimeException re) {
        throw new RuntimeException("Problem comparing field " + fieldName 
            + " on objects: " + className(first) + ", " + className(second));
      }
      
      
    }
    return differentFields;
  }
  
  /**
   * clone an object, assign primitives, Strings, maps of string attributes.  Clone GrouperCloneable fields.
   * @param <T> the type
   * @param object  the object to clone
   * @param fieldsToClone the desired fields from the object
   * @return the cloned object or null if input is null
   */
  @SuppressWarnings("unchecked")
  public static <T> T clone(T object, Set<String> fieldsToClone) {
    
    //make a return object
    T result = (T)newInstance(object.getClass());
    
    cloneFields(object, result, fieldsToClone);
    
    return result;
  }
  
  /**
   * clone an object, assign primitives, Strings, maps of string attributes.  Clone GrouperCloneable fields.
   * @param <T> the type
   * @param object  the object to clone
   * @param result  the resulting object
   * @param fieldsToClone the desired fields from the object
   */
  public static <T> void cloneFields(T object, T result,
      Set<String> fieldsToClone) {
    
    if (object == result) {
      return;
    }
    
    //if either null, then all fields are different
    if (object == null || result == null) {
      throw new RuntimeException("Cant copy from or to null: " + className(object) + ", " + className(result));
    }
    
    Class<?> fieldValueClass = null;
    
    for (String fieldName : nonNull(fieldsToClone)) {
      try {
        
        Object fieldValue = fieldValue(object, fieldName);
        fieldValueClass = fieldValue == null ? null : fieldValue.getClass();
        
        Object fieldValueToAssign = cloneValue(fieldValue);
        
        //assign the field to the clone
        assignField(result, fieldName, fieldValueToAssign);
        
      } catch (RuntimeException re) {
        throw new RuntimeException("Problem cloning field: " + object.getClass() 
              + ", " + fieldName + ", " + fieldValueClass, re);
      }
    }
  }
  
  /**
   * helper method to clone the value of a field.  just returns the same
   * reference for primitives and immutables.  Will subclone GrouperCloneables, 
   * and will throw exception if not expecting the type.  Will clone sets, lists, maps.
   * @param <T> template
   * 
   * @param value The value to clone
   * @return the cloned value
   */
  @SuppressWarnings("unchecked")
  public static <T> T cloneValue(T value) {

    Object clonedValue = value;
    
    if (value == null || value instanceof String 
        || value.getClass().isPrimitive() || value instanceof Number
        || value instanceof Boolean
        || value instanceof Date) {
      //clone things
      //for strings, and immutable classes, just assign
      //nothing to do, just assign the value
    } else if (value instanceof Map) {
      clonedValue = new LinkedHashMap();
      Map mapValue = (Map)value;
      Map clonedMapValue = (Map)clonedValue;
      for (Object key : mapValue.keySet()) {
        clonedMapValue.put(cloneValue(key), cloneValue(mapValue.get(key)));
      }
    } else if (value instanceof Set) {
        clonedValue = new LinkedHashSet();
        Set setValue = (Set)value;
        Set clonedSetValue = (Set)clonedValue;
        for (Object each : setValue) {
          clonedSetValue.add(cloneValue(each));
        }
    } else if (value instanceof List) {
      clonedValue = new ArrayList();
      List listValue = (List)value;
      List clonedListValue = (List)clonedValue;
      for (Object each : listValue) {
        clonedListValue.add(cloneValue(each));
      }
    } else if (value.getClass().isArray()) {
      clonedValue = Array.newInstance(value.getClass().getComponentType(), Array.getLength(value));
      for (int i=0;i<Array.getLength(value);i++) {
        Array.set(clonedValue, i, cloneValue(Array.get(value, i)));
      }
      
      
    } else {

      //this means let's add support for a new type of object
      throw new RuntimeException("Unexpected class in clone method: " + value.getClass());
    
    }
    return (T)clonedValue;
  }
  
  /**
   * simple method to get method names
   * @param theClass
   *          class with methods
   * @param superclassToStopAt 
   *          when recursing, stop at this class
   * @param includeSuperclassToStopAt 
   *          when true, bound is inclusive of stop class
   * @param includeStaticMethods 
   *          when true, include static methods (otherwise static methods are excluded)
   * @return the set of method names
   */
  public static Set<String> methodNames(Class<?> theClass, Class<?> superclassToStopAt, 
      boolean includeSuperclassToStopAt, boolean includeStaticMethods) {

    Set<Method> methods = new LinkedHashSet<Method>();
    methodsHelper(theClass, superclassToStopAt, includeSuperclassToStopAt, includeStaticMethods, 
        null, false, methods);
    Set<String> methodNames = new HashSet<String>();
    for (Method method : methods) {
      methodNames.add(method.getName());
    }
    return methodNames;
  }

  /**
   * get the set of methods and add them to the provided set
   * @param theClass
   *          class with methods
   * @param superclassToStopAt 
   *          when recursing, stop at this class
   * @param includeSuperclassToStopAt 
   *          when true, bound is inclusive of stop class
   * @param includeStaticMethods
   *          when true, include static methods (otherwise static methods are excluded)
   * @param markerAnnotation 
   *          a marker annotation
   * @param includeAnnotation 
   *          when true, include annotation
   * @param methodSet
   *            Holds resulting Methods
   * @see Class#getDeclaredMethods()
   */
  public static void methodsHelper(Class<?> theClass, Class<?> superclassToStopAt, 
      boolean includeSuperclassToStopAt,
      boolean includeStaticMethods, Class<? extends Annotation> markerAnnotation, 
      boolean includeAnnotation, Set<Method> methodSet) {
    Method[] methods = theClass.getDeclaredMethods();
    if (length(methods) != 0) {
      for (Method method : methods) {
        // if not static, then continue
        if (!includeStaticMethods
            && Modifier.isStatic(method.getModifiers())) {
          continue;
        }
        // if checking for annotation
        if (markerAnnotation != null
            && (includeAnnotation != method
                .isAnnotationPresent(markerAnnotation))) {
          continue;
        }
        // go for it
        methodSet.add(method);
      }
    }
    // see if done recursing (if superclassToStopAt is null, then stop at
    // Object
    if (theClass.equals(superclassToStopAt)
        || theClass.equals(Object.class)) {
      return;
    }
    Class superclass = theClass.getSuperclass();
    if (!includeSuperclassToStopAt && superclass.equals(superclassToStopAt)) {
      return;
    }
    // recurse
    methodsHelper(superclass, superclassToStopAt,
        includeSuperclassToStopAt, includeStaticMethods,
        markerAnnotation, includeAnnotation, methodSet);
    
  }
  
  /**
   * get the method
   * @param theClass
   *          class with methods
   * @param methodName 
   *          the method name
   * @param paramTypesOrArrayOrList
   *          types of the params
   * @param superclassToStopAt 
   *          the super class beyond which no more searching is performed
   * @param includeSuperclassToStopAt 
   *          when true, the superclassToStopAt is included in the search
   * @param isStaticOrInstance true if static
   * @param markerAnnotation the annotation to look for
   * @param includeAnnotation when true, include the annotation
   * @return the method or null if not found
   *            
   */
  public static Method method(Class<?> theClass, 
      String methodName, Object paramTypesOrArrayOrList,
      Class<?> superclassToStopAt, 
      boolean includeSuperclassToStopAt,
      boolean isStaticOrInstance, Class<? extends Annotation> markerAnnotation, 
      boolean includeAnnotation) {

    Class[] paramTypesArray = (Class[]) toArray(paramTypesOrArrayOrList);

    Method method = null;
    
    try {
      method = theClass.getDeclaredMethod(methodName, paramTypesArray);
    } catch (NoSuchMethodException nsme) {
      //this is ok
    } catch (Exception e) {
      throw new RuntimeException("Problem retrieving method: " + theClass.getSimpleName() + ", " + methodName, e);
    }
    
    if (method != null) {
      //we found a method, make sure it is valid
      // if not static, then return null (dont worry about superclass)
      if (!isStaticOrInstance
          && Modifier.isStatic(method.getModifiers())) {
        return null;
      }
      // if checking for annotation, if not there, then recurse
      if (markerAnnotation == null
          || (includeAnnotation == method
              .isAnnotationPresent(markerAnnotation))) {
        return method;
      }
    }
    // see if done recursing (if superclassToStopAt is null, then stop at
    // Object
    if (theClass.equals(superclassToStopAt)
        || theClass.equals(Object.class)) {
      return null;
    }
    Class superclass = theClass.getSuperclass();
    if (!includeSuperclassToStopAt && superclass.equals(superclassToStopAt)) {
      return null;
    }
    // recurse
    return method(superclass, methodName, paramTypesArray, superclassToStopAt,
        includeSuperclassToStopAt, isStaticOrInstance, markerAnnotation, includeAnnotation);
  }
  
  /**
   * get all field names from a class, including superclasses (if specified)
   * 
   * @param theClass
   *            to look for fields in
   * @param superclassToStopAt
   *            to go up to or null to go up to Object
   * @param fieldType
   *            is the type of the field to get
   * @param includeSuperclassToStopAt
   *            if we should include the superclass
   * @param includeStaticFields
   *            if include static fields
   * @param includeFinalFields
   *            if final fields should be included
   * @param markerAnnotation
   *            if this is not null, then if the field has this annotation,
   *            then do not include in list
   * @param fieldSet
   *            set to add fields to
   * @param includeAnnotation
   *            if include or exclude
   */
  @SuppressWarnings("unchecked")
  private static void fieldsHelper(Class theClass, Class superclassToStopAt,
      Class<?> fieldType, boolean includeSuperclassToStopAt,
      boolean includeStaticFields, boolean includeFinalFields,
      Class<? extends Annotation> markerAnnotation, Set<Field> fieldSet,
      boolean includeAnnotation) {
    Field[] fields = theClass.getDeclaredFields();
    if (length(fields) != 0) {
      for (Field field : fields) {
        // if checking for type, and not right type, continue
        if (fieldType != null
            && !fieldType.isAssignableFrom(field.getType())) {
          continue;
        }
        // if not static, then continue
        if (!includeStaticFields
            && Modifier.isStatic(field.getModifiers())) {
          continue;
        }
        // if not final constinue
        if (!includeFinalFields
            && Modifier.isFinal(field.getModifiers())) {
          continue;
        }
        // if checking for annotation
        if (markerAnnotation != null
            && (includeAnnotation != field
                .isAnnotationPresent(markerAnnotation))) {
          continue;
        }
        // go for it
        fieldSet.add(field);
      }
    }
    // see if done recursing (if superclassToStopAt is null, then stop at
    // Object
    if (theClass.equals(superclassToStopAt)
        || theClass.equals(Object.class)) {
      return;
    }
    Class superclass = theClass.getSuperclass();
    if (!includeSuperclassToStopAt && superclass.equals(superclassToStopAt)) {
      return;
    }
    // recurse
    fieldsHelper(superclass, superclassToStopAt, fieldType,
        includeSuperclassToStopAt, includeStaticFields,
        includeFinalFields, markerAnnotation, fieldSet,
        includeAnnotation);
  }

  /**
   * find out a field value
   * 
   * @param theClass
   *            the class which has the method
   * @param invokeOn
   *            to call on or null for static
   * @param fieldName
   *            method name to call
   * @param callOnSupers
   *            if static and method not exists, try on supers
   * @param overrideSecurity
   *            true to call on protected or private etc methods
   * @return the current value
   */
  public static Object fieldValue(Class theClass, Object invokeOn,
      String fieldName, boolean callOnSupers, boolean overrideSecurity) {
    Field field = null;

    // only if the method exists, try to execute
    try {
      // ok if null
      if (theClass == null) {
        theClass = invokeOn.getClass();
      }
      field = field(theClass, fieldName, callOnSupers, true);
      return fieldValue(field, invokeOn, overrideSecurity);
    } catch (Exception e) {
      throw new RuntimeException("Cant execute reflection field: "
          + fieldName + ", on: " + className(invokeOn), e);
    }
  }

  /**
   * get the value of a field, override security if needbe
   * 
   * @param field the field
   * @param invokeOn the object on which to invoke the field
   * @return the value of the field
   */
  public static Object fieldValue(Field field, Object invokeOn) {
    return fieldValue(field, invokeOn, true);
  }

  /**
   * get the value of a field
   * 
   * @param field the field
   * @param invokeOn the object on which to invoke the field
   * @param overrideSecurity when true, set accessible on the field
   * @return the value of the field
   * @see java.lang.reflect.Field#get(Object)
   */
  public static Object fieldValue(Field field, Object invokeOn,
      boolean overrideSecurity) {
    if (overrideSecurity) {
      field.setAccessible(true);
    }
    try {
      return field.get(invokeOn);
    } catch (Exception e) {
      throw new RuntimeException("Cant execute reflection field: "
          + field.getName() + ", on: " + className(invokeOn), e);

    }

  }

  /**
   * find out a field value (invoke on supers, override security)
   * 
   * @param invokeOn
   *            to call on or null for static
   * @param fieldName
   *            method name to call
   * @return the current value
   */
  public static Object fieldValue(Object invokeOn, String fieldName) {
    return fieldValue(null, invokeOn, fieldName, true, true);
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
   * helper method for calling a method with no params (could be in
   * superclass)
   * 
   * @param theClass
   *            the class which has the method
   * @param invokeOn
   *            to call on or null for static
   * @param methodName
   *            method name to call
   * @return the data
   */
  public static Object callMethod(Class theClass, Object invokeOn,
      String methodName) {
    return callMethod(theClass, invokeOn, methodName, null, null);
  }

  /**
   * helper method for calling a method (could be in superclass)
   * 
   * @param theClass
   *            the class which has the method
   * @param invokeOn
   *            to call on or null for static
   * @param methodName
   *            method name to call
   * @param paramTypesOrArrayOrList
   *            types of the params
   * @param paramsOrListOrArray
   *            data
   * @return the data
   */
  public static Object callMethod(Class theClass, Object invokeOn,
      String methodName, Object paramTypesOrArrayOrList,
      Object paramsOrListOrArray) {
    return callMethod(theClass, invokeOn, methodName,
        paramTypesOrArrayOrList, paramsOrListOrArray, true);
  }

  /**
   * helper method for calling a method
   * 
   * @param theClass
   *            the class which has the method
   * @param invokeOn
   *            to call on or null for static
   * @param methodName
   *            method name to call
   * @param paramTypesOrArrayOrList
   *            types of the params
   * @param paramsOrListOrArray
   *            data
   * @param callOnSupers
   *            if static and method not exists, try on supers
   * @return the data
   */
  public static Object callMethod(Class theClass, Object invokeOn,
      String methodName, Object paramTypesOrArrayOrList,
      Object paramsOrListOrArray, boolean callOnSupers) {
    return callMethod(theClass, invokeOn, methodName,
        paramTypesOrArrayOrList, paramsOrListOrArray, callOnSupers,
        false);
  }

  /**
   * construct an instance by reflection
   * @param <T> the type 
   * @param theClass the class
   * @param types the types array
   * @param args the arguments array
   * @return the instance
   */
  public static <T> T construct(Class<T> theClass, Class[] types, Object[] args) {
    try {
      Constructor<T> constructor = theClass.getConstructor(types);
      
      return constructor.newInstance(args);
      
    } catch (Exception e) {
      throw new RuntimeException("Having trouble with constructor for class: " + theClass.getSimpleName()
          + " and args: " + classesString(types), e);
     }
  }
  
  /**
   * helper method for calling a method
   * 
   * @param theClass
   *            the class which has the method
   * @param invokeOn
   *            to call on or null for static
   * @param methodName
   *            method name to call
   * @param paramTypesOrArrayOrList
   *            types of the params
   * @param paramsOrListOrArray
   *            data
   * @param callOnSupers
   *            if static and method not exists, try on supers
   * @param overrideSecurity
   *            true to call on protected or private etc methods
   * @return the data
   */
  public static Object callMethod(Class theClass, Object invokeOn,
      String methodName, Object paramTypesOrArrayOrList,
      Object paramsOrListOrArray, boolean callOnSupers,
      boolean overrideSecurity) {
    Method method = null;

    Class[] paramTypesArray = (Class[]) toArray(paramTypesOrArrayOrList);

    try {
      method = theClass.getDeclaredMethod(methodName, paramTypesArray);
      if (overrideSecurity) {
        method.setAccessible(true);
      }
    } catch (Exception e) {
      // if method not found
      if (e instanceof NoSuchMethodException) {
        // if traversing up, and not Object, and not instance method
        // CH 070425 not sure why invokeOn needs to be null, removing
        // this
        if (callOnSupers /* && invokeOn == null */
            && !theClass.equals(Object.class)) {
          return callMethod(theClass.getSuperclass(), invokeOn,
              methodName, paramTypesOrArrayOrList,
              paramsOrListOrArray, callOnSupers, overrideSecurity);
        }
      }
      throw new RuntimeException("Problem calling method " + methodName
          + " on " + theClass.getName(), e);
    }

    return invokeMethod(method, invokeOn, paramsOrListOrArray);

  }
  
  /** pass this in the invokeOn to signify no params */
  private static final Object NO_PARAMS = new Object();
  
  /**
   * Safely invoke a reflection method that takes no args
   * 
   * @param method
   *            to invoke
   * @param invokeOn the object on which to invoke the method
   * if NO_PARAMS then will not pass in params.
   * @return the result
   */
  public static Object invokeMethod(Method method, Object invokeOn) {
    return invokeMethod(method, invokeOn, NO_PARAMS);
  }

  /**
   * Safely invoke a reflection method
   * 
   * @param method
   *            to invoke
   * @param invokeOn the object on which to invoke the method
   * @param paramsOrListOrArray must be an arg.  If null, will pass null.
   * if NO_PARAMS then will not pass in params.
   * @return the result
   */
  public static Object invokeMethod(Method method, Object invokeOn,
      Object paramsOrListOrArray) {

    Object[] args = paramsOrListOrArray == NO_PARAMS ? null : (Object[]) toArray(paramsOrListOrArray);

    //we want to make sure things are accessible
    method.setAccessible(true);

    //only if the method exists, try to execute
    Object result = null;
    Exception e = null;
    try {
      result = method.invoke(invokeOn, args);
    } catch (IllegalAccessException iae) {
      e = iae;
    } catch (IllegalArgumentException iae) {
      e = iae;
    } catch (InvocationTargetException ite) {
      //this means the underlying call caused exception... its ok if runtime
      if (ite.getCause() instanceof RuntimeException) {
        throw (RuntimeException)ite.getCause();
      }
      //else throw as invocation target...
      e = ite;
    }
    if (e != null) {
      throw new RuntimeException("Cant execute reflection method: "
          + method.getName() + ", on: " + className(invokeOn)
          + ", with args: " + classNameCollection(args), e);
    }
    return result;
  }

  /**
   * Convert a list to an array with the type of the first element e.g. if it
   * is a list of Person objects, then the array is Person[]
   * 
   * @param objectOrArrayOrCollection
   *            is a list
   * @return the array of objects with type of the first element in the list
   */
  public static Object toArray(Object objectOrArrayOrCollection) {
    // do this before length since if array with null in it, we want ti get
    // it back
    if (objectOrArrayOrCollection != null
        && objectOrArrayOrCollection.getClass().isArray()) {
      return objectOrArrayOrCollection;
    }
    int length = length(objectOrArrayOrCollection);
    if (length == 0) {
      return null;
    }

    if (objectOrArrayOrCollection instanceof Collection) {
      Collection collection = (Collection) objectOrArrayOrCollection;
      Object first = collection.iterator().next();
      return toArray(collection, first == null ? Object.class : first
          .getClass());
    }
    // make an array of the type of object passed in, size one
    Object array = Array.newInstance(objectOrArrayOrCollection.getClass(),
        1);
    Array.set(array, 0, objectOrArrayOrCollection);
    return array;
  }

  /**
   * convert a list into an array of type of theClass
   * @param <T> is the type of the array
   * @param collection list to convert
   * @param theClass type of array to return
   * @return array of type theClass[] filled with the objects from list
   */
  @SuppressWarnings("unchecked")
  public static <T> T[] toArray(Collection collection, Class<T> theClass) {
    if (collection == null || collection.size() == 0) {
      return null;
    }

    return (T[])collection.toArray((Object[]) Array.newInstance(theClass,
        collection.size()));

  }

  /**
   * helper method for calling a static method up the stack. method takes no
   * args (could be in superclass)
   * 
   * @param theClass
   *            the class which has the method
   * @param methodName
   *            method name to call
   * @return the data
   */
  public static Object callMethod(Class theClass, String methodName) {
    return callMethod(theClass, null, methodName, null, null);
  }

  /**
   * helper method for calling a static method with no params
   * 
   * @param theClass
   *            the class which has the method
   * @param methodName
   *            method name to call
   * @param callOnSupers
   *            if we should try the super classes if not exists in this class
   * @return the data
   */
  public static Object callMethod(Class theClass, String methodName,
      boolean callOnSupers) {
    return callMethod(theClass, null, methodName, null, null, callOnSupers);
  }

  /**
   * helper method for calling a static method up the stack
   * 
   * @param theClass
   *            the class which has the method
   * @param methodName
   *            method name to call
   * @param paramTypesOrArrayOrList
   *            types of the params
   * @param paramsOrListOrArray
   *            data
   * @return the data
   */
  public static Object callMethod(Class theClass, String methodName,
      Object paramTypesOrArrayOrList, Object paramsOrListOrArray) {
    return callMethod(theClass, null, methodName, paramTypesOrArrayOrList,
        paramsOrListOrArray);
  }

  /**
   * helper method for calling a method with no params (could be in
   * superclass), will override security
   * 
   * @param invokeOn
   *            instance to invoke on
   * @param methodName
   *            method name to call not exists in this class
   * @return the data
   */
  public static Object callMethod(Object invokeOn, String methodName) {
    if (invokeOn == null) {
      throw new NullPointerException("invokeOn is null: " + methodName);
    }
    return callMethod(invokeOn.getClass(), invokeOn, methodName, null,
        null, true, true);
  }

  /**
   * replace a string or strings from a string, and put the output in a string
   * buffer. This does not recurse
   * 
   * @param text
   *            string to look in
   * @param searchFor
   *            string array to search for
   * @param replaceWith
   *            string array to replace with
   * @return the string
   */
  public static String replace(String text, Object searchFor,
      Object replaceWith) {
    return replace(null, null, text, searchFor, replaceWith, false, 0,
        false);
  }

  /**
   * replace a string or strings from a string, and put the output in a string
   * buffer
   * 
   * @param text
   *            string to look in
   * @param searchFor
   *            string array to search for
   * @param replaceWith
   *            string array to replace with
   * @param recurse
   *            if true then do multiple replaces (on the replacements)
   * @return the string
   */
  public static String replace(String text, Object searchFor,
      Object replaceWith, boolean recurse) {
    return replace(null, null, text, searchFor, replaceWith, recurse,
        recurse ? length(searchFor) : 0, false);
  }

  /**
   * replace a string or strings from a string, and put the output in a string
   * buffer
   * 
   * @param text
   *            string to look in
   * @param searchFor
   *            string array to search for
   * @param replaceWith
   *            string array to replace with
   * @param recurse
   *            if true then do multiple replaces (on the replacements)
   * @param removeIfFound
   *            true if removing from searchFor and replaceWith if found
   * @return the string
   */
  public static String replace(String text, Object searchFor,
      Object replaceWith, boolean recurse, boolean removeIfFound) {
    return replace(null, null, text, searchFor, replaceWith, recurse,
        recurse ? length(searchFor) : 0, removeIfFound);
  }

  /**
   * <p>
   * Replaces all occurrences of a String within another String.
   * </p>
   * 
   * <p>
   * A <code>null</code> reference passed to this method is a no-op.
   * </p>
   * 
   * <pre>
   * replace(null, *, *)        = null
   * replace(&quot;&quot;, *, *)          = &quot;&quot;
   * replace(&quot;any&quot;, null, *)    = &quot;any&quot;
   * replace(&quot;any&quot;, *, null)    = &quot;any&quot;
   * replace(&quot;any&quot;, &quot;&quot;, *)      = &quot;any&quot;
   * replace(&quot;aba&quot;, &quot;a&quot;, null)  = &quot;aba&quot;
   * replace(&quot;aba&quot;, &quot;a&quot;, &quot;&quot;)    = &quot;b&quot;
   * replace(&quot;aba&quot;, &quot;a&quot;, &quot;z&quot;)   = &quot;zbz&quot;
   * </pre>
   * 
   * @see #replace(String text, String repl, String with, int max)
   * @param text
   *            text to search and replace in, may be null
   * @param repl
   *            the String to search for, may be null
   * @param with
   *            the String to replace with, may be null
   * @return the text with any replacements processed, <code>null</code> if
   *         null String input
   */
  public static String replace(String text, String repl, String with) {
    return replace(text, repl, with, -1);
  }

  /**
   * <p>
   * Replaces a String with another String inside a larger String, for the
   * first <code>max</code> values of the search String.
   * </p>
   * 
   * <p>
   * A <code>null</code> reference passed to this method is a no-op.
   * </p>
   * 
   * <pre>
   * replace(null, *, *, *)         = null
   * replace(&quot;&quot;, *, *, *)           = &quot;&quot;
   * replace(&quot;any&quot;, null, *, *)     = &quot;any&quot;
   * replace(&quot;any&quot;, *, null, *)     = &quot;any&quot;
   * replace(&quot;any&quot;, &quot;&quot;, *, *)       = &quot;any&quot;
   * replace(&quot;any&quot;, *, *, 0)        = &quot;any&quot;
   * replace(&quot;abaa&quot;, &quot;a&quot;, null, -1) = &quot;abaa&quot;
   * replace(&quot;abaa&quot;, &quot;a&quot;, &quot;&quot;, -1)   = &quot;b&quot;
   * replace(&quot;abaa&quot;, &quot;a&quot;, &quot;z&quot;, 0)   = &quot;abaa&quot;
   * replace(&quot;abaa&quot;, &quot;a&quot;, &quot;z&quot;, 1)   = &quot;zbaa&quot;
   * replace(&quot;abaa&quot;, &quot;a&quot;, &quot;z&quot;, 2)   = &quot;zbza&quot;
   * replace(&quot;abaa&quot;, &quot;a&quot;, &quot;z&quot;, -1)  = &quot;zbzz&quot;
   * </pre>
   * 
   * @param text
   *            text to search and replace in, may be null
   * @param repl
   *            the String to search for, may be null
   * @param with
   *            the String to replace with, may be null
   * @param max
   *            maximum number of values to replace, or <code>-1</code> if
   *            no maximum
   * @return the text with any replacements processed, <code>null</code> if
   *         null String input
   */
  public static String replace(String text, String repl, String with, int max) {
    if (text == null || isEmpty(repl) || with == null || max == 0) {
      return text;
    }

    StringBuffer buf = new StringBuffer(text.length());
    int start = 0, end = 0;
    while ((end = text.indexOf(repl, start)) != -1) {
      buf.append(text.substring(start, end)).append(with);
      start = end + repl.length();

      if (--max == 0) {
        break;
      }
    }
    buf.append(text.substring(start));
    return buf.toString();
  }

  /**
   * <p>
   * Checks if a String is empty ("") or null.
   * </p>
   * 
   * <pre>
   * isEmpty(null)      = true
   * isEmpty(&quot;&quot;)        = true
   * isEmpty(&quot; &quot;)       = false
   * isEmpty(&quot;bob&quot;)     = false
   * isEmpty(&quot;  bob  &quot;) = false
   * </pre>
   * 
   * <p>
   * NOTE: This method changed in Lang version 2.0. It no longer trims the
   * String. That functionality is available in isBlank().
   * </p>
   * 
   * @param str
   *            the String to check, may be null
   * @return <code>true</code> if the String is empty or null
   */
  public static boolean isEmpty(String str) {
    return str == null || str.length() == 0;
  }

  /**
   * replace a string or strings from a string, and put the output in a string
   * buffer. This does not recurse
   * 
   * @param outBuffer
   *            stringbuffer to write to
   * @param text
   *            string to look in
   * @param searchFor
   *            string array to search for
   * @param replaceWith
   *            string array to replace with
   */
  public static void replace(StringBuffer outBuffer, String text,
      Object searchFor, Object replaceWith) {
    replace(outBuffer, null, text, searchFor, replaceWith, false, 0, false);
  }

  /**
   * replace a string or strings from a string, and put the output in a string
   * buffer
   * 
   * @param outBuffer
   *            stringbuffer to write to
   * @param text
   *            string to look in
   * @param searchFor
   *            string array to search for
   * @param replaceWith
   *            string array to replace with
   * @param recurse
   *            if true then do multiple replaces (on the replacements)
   */
  public static void replace(StringBuffer outBuffer, String text,
      Object searchFor, Object replaceWith, boolean recurse) {
    replace(outBuffer, null, text, searchFor, replaceWith, recurse,
        recurse ? length(searchFor) : 0, false);
  }

  /**
   * replace a string with other strings, and either write to outWriter, or
   * StringBuffer, and if StringBuffer potentially return a string. If
   * outBuffer and outWriter are null, then return the String
   * 
   * @param outBuffer
   *            stringbuffer to write to, or null to not
   * @param outWriter
   *            Writer to write to, or null to not.
   * @param text
   *            string to look in
   * @param searchFor
   *            string array to search for, or string, or list
   * @param replaceWith
   *            string array to replace with, or string, or list
   * @param recurse
   *            if true then do multiple replaces (on the replacements)
   * @param timeToLive
   *            if recursing, prevent endless loops
   * @param removeIfFound
   *            true if removing from searchFor and replaceWith if found
   * @return the String if outBuffer and outWriter are null
   * @throws IndexOutOfBoundsException
   *             if the lengths of the arrays are not the same (null is ok,
   *             and/or size 0)
   * @throws IllegalArgumentException
   *             if the search is recursive and there is an endless loop due
   *             to outputs of one being inputs to another
   */
  private static String replace(StringBuffer outBuffer, Writer outWriter,
      String text, Object searchFor, Object replaceWith, boolean recurse,
      int timeToLive, boolean removeIfFound) {

    // if recursing, we need to get the string, then print to buffer (since
    // we need multiple passes)
    if (!recurse) {
      return replaceHelper(outBuffer, outWriter, text, searchFor,
          replaceWith, recurse, timeToLive, removeIfFound);
    }
    // get the string
    String result = replaceHelper(null, null, text, searchFor, replaceWith,
        recurse, timeToLive, removeIfFound);
    if (outBuffer != null) {
      outBuffer.append(result);
      return null;
    }

    if (outWriter != null) {
      try {
        outWriter.write(result);
      } catch (IOException ioe) {
        throw new RuntimeException(ioe);
      }
      return null;
    }

    return result;

  }

  /**
   * replace a string or strings from a string, and put the output in a string
   * buffer. This does not recurse
   * 
   * @param outWriter
   *            writer to write to
   * @param text
   *            string to look in
   * @param searchFor
   *            string array to search for
   * @param replaceWith
   *            string array to replace with
   */
  public static void replace(Writer outWriter, String text, Object searchFor,
      Object replaceWith) {
    replace(null, outWriter, text, searchFor, replaceWith, false, 0, false);
  }

  /**
   * replace a string or strings from a string, and put the output in a string
   * buffer
   * 
   * @param outWriter
   *            writer to write to
   * @param text
   *            string to look in
   * @param searchFor
   *            string array to search for
   * @param replaceWith
   *            string array to replace with
   * @param recurse
   *            if true then do multiple replaces (on the replacements)
   */
  public static void replace(Writer outWriter, String text, Object searchFor,
      Object replaceWith, boolean recurse) {
    replace(null, outWriter, text, searchFor, replaceWith, recurse,
        recurse ? length(searchFor) : 0, false);
  }

  /**
   * replace a string with other strings, and either write to outWriter, or
   * StringBuffer, and if StringBuffer potentially return a string. If
   * outBuffer and outWriter are null, then return the String
   * 
   * @param outBuffer
   *            stringbuffer to write to, or null to not
   * @param outWriter
   *            Writer to write to, or null to not.
   * @param text
   *            string to look in
   * @param searchFor
   *            string array to search for, or string, or list
   * @param replaceWith
   *            string array to replace with, or string, or list
   * @param recurse
   *            if true then do multiple replaces (on the replacements)
   * @param timeToLive
   *            if recursing, prevent endless loops
   * @param removeIfFound
   *            true if removing from searchFor and replaceWith if found
   * @return the String if outBuffer and outWriter are null
   * @throws IllegalArgumentException
   *             if the search is recursive and there is an endless loop due
   *             to outputs of one being inputs to another
   * @throws IndexOutOfBoundsException
   *             if the lengths of the arrays are not the same (null is ok,
   *             and/or size 0)
   */
  private static String replaceHelper(StringBuffer outBuffer,
      Writer outWriter, String text, Object searchFor,
      Object replaceWith, boolean recurse, int timeToLive,
      boolean removeIfFound) {

    try {
      // if recursing, this shouldnt be less than 0
      if (timeToLive < 0) {
        throw new IllegalArgumentException("TimeToLive under 0: "
            + timeToLive + ", " + text);
      }

      int searchForLength = length(searchFor);
      boolean done = false;
      // no need to do anything
      if (isEmpty(text)) {
        return text;
      }
      // need to write the input to output, later
      if (searchForLength == 0) {
        done = true;
      }

      boolean[] noMoreMatchesForReplIndex = null;
      int inputIndex = -1;
      int replaceIndex = -1;
      long resultPacked = -1;

      if (!done) {
        // make sure lengths are ok, these need to be equal
        if (searchForLength != length(replaceWith)) {
          throw new IndexOutOfBoundsException("Lengths dont match: "
              + searchForLength + ", " + length(replaceWith));
        }

        // keep track of which still have matches
        noMoreMatchesForReplIndex = new boolean[searchForLength];

        // index of replace array that will replace the search string
        // found
        

        resultPacked = findNextIndexHelper(searchForLength, searchFor,
            replaceWith, 
            noMoreMatchesForReplIndex, text, 0);

        inputIndex = unpackInt(resultPacked, true);
        replaceIndex = unpackInt(resultPacked, false);
      }

      // get a good guess on the size of the result buffer so it doesnt
      // have to double if it
      // goes over a bit
      boolean writeToWriter = outWriter != null;

      // no search strings found, we are done
      if (done || inputIndex == -1) {
        if (writeToWriter) {
          outWriter.write(text, 0, text.length());
          return null;
        }
        if (outBuffer != null) {
          appendSubstring(outBuffer, text, 0, text.length());
          return null;
        }
        return text;
      }

      // no buffer if writing to writer
      StringBuffer bufferToWriteTo = outBuffer != null ? outBuffer
          : (writeToWriter ? null : new StringBuffer(text.length()
              + replaceStringsBufferIncrease(text, searchFor,
                  replaceWith)));

      String searchString = null;
      String replaceString = null;

      int start = 0;

      while (inputIndex != -1) {

        searchString = (String) get(searchFor, replaceIndex);
        replaceString = (String) get(replaceWith, replaceIndex);
        if (writeToWriter) {
          outWriter.write(text, start, inputIndex - start);
          outWriter.write(replaceString);
        } else {
          appendSubstring(bufferToWriteTo, text, start, inputIndex)
              .append(replaceString);
        }

        if (removeIfFound) {
          // better be an iterator based find replace
          searchFor = remove(searchFor, replaceIndex);
          replaceWith = remove(replaceWith, replaceIndex);
          noMoreMatchesForReplIndex = (boolean[])remove(noMoreMatchesForReplIndex, replaceIndex);
          // we now have a lesser size if we removed one
          searchForLength--;
        }

        start = inputIndex + searchString.length();

        resultPacked = findNextIndexHelper(searchForLength, searchFor,
            replaceWith, 
            noMoreMatchesForReplIndex, text, start);
        inputIndex = unpackInt(resultPacked, true);
        replaceIndex = unpackInt(resultPacked, false);
      }
      if (writeToWriter) {
        outWriter.write(text, start, text.length() - start);

      } else {
        appendSubstring(bufferToWriteTo, text, start, text.length());
      }

      // no need to convert to string if incoming buffer or writer
      if (writeToWriter || outBuffer != null) {
        if (recurse) {
          throw new IllegalArgumentException(
              "Cannot recurse and write to existing buffer or writer!");
        }
        return null;
      }
      String resultString = bufferToWriteTo.toString();

      if (recurse) {
        return replaceHelper(outBuffer, outWriter, resultString,
            searchFor, replaceWith, recurse, timeToLive - 1, false);
      }
      // this might be null for writer
      return resultString;
    } catch (IOException ioe) {
      throw new RuntimeException(ioe);
    }
  }

  /**
   * give a best guess on buffer increase for String[] replace get a good
   * guess on the size of the result buffer so it doesnt have to double if it
   * goes over a bit
   * 
   * @param text
   * @param repl
   * @param with
   * @return the increase, with 20% cap
   */
  static int replaceStringsBufferIncrease(String text, Object repl,
      Object with) {
    // count the greaters
    int increase = 0;
    Iterator iteratorReplace = iterator(repl);
    Iterator iteratorWith = iterator(with);
    int replLength = length(repl);
    String currentRepl = null;
    String currentWith = null;
    for (int i = 0; i < replLength; i++) {
      currentRepl = (String) next(repl, iteratorReplace, i);
      currentWith = (String) next(with, iteratorWith, i);
      if (currentRepl == null || currentWith == null) {
        throw new NullPointerException("Replace string is null: "
            + text + ", " + currentRepl + ", " + currentWith);
      }
      int greater = currentWith.length() - currentRepl.length();
      increase += greater > 0 ? 3 * greater : 0; // assume 3 matches
    }
    // have upper-bound at 20% increase, then let Java take over
    increase = Math.min(increase, text.length() / 5);
    return increase;
  }

  /**
   * Helper method to find the next match in an array of strings replace
   * 
   * @param searchForLength
   * @param searchFor
   * @param replaceWith
   * @param noMoreMatchesForReplIndex
   * @param input
   * @param start
   *            is where to start looking
   * @return result packed into a long, inputIndex first, then replaceIndex
   */
  private static long findNextIndexHelper(int searchForLength,
      Object searchFor, Object replaceWith, boolean[] noMoreMatchesForReplIndex,
      String input, int start) {

    int inputIndex = -1;
    int replaceIndex = -1;

    Iterator iteratorSearchFor = iterator(searchFor);
    Iterator iteratorReplaceWith = iterator(replaceWith);

    String currentSearchFor = null;
    String currentReplaceWith = null;
    int tempIndex = -1;
    for (int i = 0; i < searchForLength; i++) {
      currentSearchFor = (String) next(searchFor, iteratorSearchFor, i);
      currentReplaceWith = (String) next(replaceWith,
          iteratorReplaceWith, i);
      if (noMoreMatchesForReplIndex[i] || isEmpty(currentSearchFor)
          || currentReplaceWith == null) {
        continue;
      }
      tempIndex = input.indexOf(currentSearchFor, start);

      // see if we need to keep searching for this
      noMoreMatchesForReplIndex[i] = tempIndex == -1;

      if (tempIndex != -1 && (inputIndex == -1 || tempIndex < inputIndex)) {
        inputIndex = tempIndex;
        replaceIndex = i;
      }

    }
    // dont create an array, no more objects
    long resultPacked = packInts(inputIndex, replaceIndex);
    return resultPacked;
  }

  /**
   * pack two ints into a long. Note: the first is held in the left bits, the
   * second is held in the right bits
   * 
   * @param first
   *            is first int
   * @param second
   *            is second int
   * @return the long which has two ints in there
   */
  public static long packInts(int first, int second) {
    long result = first;
    result <<= 32;
    result |= second;
    return result;
  }

  /**
   * take a long
   * 
   * @param theLong
   *            to unpack
   * @param isFirst
   *            true for first, false for second
   * @return one of the packed ints, first or second
   */
  public static int unpackInt(long theLong, boolean isFirst) {

    int result = 0;
    // put this in the position of the second one
    if (isFirst) {
      theLong >>= 32;
    }
    // only look at right part
    result = (int) (theLong & 0xffffffff);
    return result;
  }

  /**
   * append a substring to a stringbuffer. removes dependency on substring
   * which creates objects
   * 
   * @param buf
   *            stringbuffer
   * @param string
   *            source string
   * @param start
   *            start index of source string
   * @param end
   *            end index of source string
   * @return the string buffer for chaining
   */
  private static StringBuffer appendSubstring(StringBuffer buf,
      String string, int start, int end) {
    for (int i = start; i < end; i++) {
      buf.append(string.charAt(i));
    }
    return buf;
  }

  /**
   * Get a specific index of an array or collection (note for collections and
   * iterating, it is more efficient to get an iterator and iterate
   * 
   * @param arrayOrCollection the array, List, or Collection
   * @param index the index of the desired object
   * @return the object at that index
   */
  public static Object get(Object arrayOrCollection, int index) {

    if (arrayOrCollection == null) {
      if (index == 0) {
        return null;
      }
      throw new RuntimeException("Trying to access index " + index
          + " of null");
    }

    // no need to iterator on list (e.g. FastProxyList has no iterator
    if (arrayOrCollection instanceof List) {
      return ((List) arrayOrCollection).get(index);
    }
    if (arrayOrCollection instanceof Collection) {
      Iterator iterator = iterator(arrayOrCollection);
      for (int i = 0; i < index; i++) {
        next(arrayOrCollection, iterator, i);
      }
      return next(arrayOrCollection, iterator, index);
    }

    if (arrayOrCollection.getClass().isArray()) {
      return Array.get(arrayOrCollection, index);
    }

    if (index == 0) {
      return arrayOrCollection;
    }

    throw new RuntimeException("Trying to access index " + index
        + " of and object: " + arrayOrCollection);
  }


  
  /**
   * fail safe toString for Exception blocks, and include the stack
   * if there is a problem with toString()
   * @param object object to convert to human-readable string.
   * @return the toStringSafe string
   */
  @SuppressWarnings("unchecked")
  public static String toStringSafe(Object object) {
    if (object == null) {
      return null;
    }
    
    try {
      //give size and type if collection
      if (object instanceof Collection) {
        Collection<Object> collection = (Collection<Object>) object;
        int collectionSize = collection.size();
        if (collectionSize == 0) {
          return "Empty " + object.getClass().getSimpleName();
        }
        Object first = collection.iterator().next();
        return object.getClass().getSimpleName() + " of size " 
          + collectionSize + " with first type: " + 
          (first == null ? null : first.getClass());
      }
    
      return object.toString();
    } catch (Exception e) {
      return "<<exception>> " + object.getClass() + ":\n" + getFullStackTrace(e) + "\n";
    }
  }

  /**
   * get the boolean value for an object, cant be null or blank
   * 
   * @param object object to convert to a boolean.  Supports string values of "true", "t", "yes" and "y" as true.
   * @return the boolean
   */
  public static boolean booleanValue(Object object) {
    // first handle blanks
    if (nullOrBlank(object)) {
      throw new RuntimeException(
          "Expecting something which can be converted to boolean, but is null or blank: '"
              + object + "'");
    }
    // its not blank, just convert
    if (object instanceof Boolean) {
      return (Boolean) object;
    }
    if (object instanceof String) {
      String string = (String) object;
      if (equalsIgnoreCase(string, "true")
          || equalsIgnoreCase(string, "t")
          || equalsIgnoreCase(string, "yes")
          || equalsIgnoreCase(string, "y")) {
        return true;
      }
      if (equalsIgnoreCase(string, "false")
          || equalsIgnoreCase(string, "f")
          || equalsIgnoreCase(string, "no")
          || equalsIgnoreCase(string, "n")) {
        return false;
      }
      throw new RuntimeException(
          "Invalid string to boolean conversion: '" + string
              + "' expecting true|false or t|f or yes|no or y|n case insensitive");
  
    }
    throw new RuntimeException("Cant convert object to boolean: "
        + object.getClass());
  
  }

  /**
   * get the boolean value for an object
   * 
   * @param object object to convert to a boolean
   * @param defaultBoolean
   *            if object is null or empty
   * @return the boolean
   */
  public static boolean booleanValue(Object object, boolean defaultBoolean) {
    if (nullOrBlank(object)) {
      return defaultBoolean;
    }
    return booleanValue(object);
  }

  /**
   * get the Boolean value for an object
   * 
   * @param object object to convert to a boolean
   * @return the Boolean or null if null or empty
   */
  public static Boolean booleanObjectValue(Object object) {
    if (nullOrBlank(object)) {
      return null;
    }
    return booleanValue(object);
  }

  /**
   * is an object null or blank
   * 
   * @param object object to test for null or String to test for blank
   * @return true if null or blank
   */
  public static boolean nullOrBlank(Object object) {
    // first handle blanks and nulls
    if (object == null) {
      return true;
    }
    if (object instanceof String && isBlank(((String) object))) {
      return true;
    }
    return false;
  
  }

  /**
   * get a getter method object for a class, potentially in superclasses
   * @param theClass the class
   * @param fieldName the field name
   * @param callOnSupers true if superclasses should be looked in for the getter
   * @param throwExceptionIfNotFound will throw runtime exception if not found
   * @return the getter object or null if not found (or exception if param is set)
   */
  public static Method getter(Class theClass, String fieldName, boolean callOnSupers, 
      boolean throwExceptionIfNotFound) {
    String getterName = getterNameFromPropertyName(fieldName);
    return getterHelper(theClass, fieldName, getterName, callOnSupers, throwExceptionIfNotFound);
  }

  /**
   * get a setter method object for a class, potentially in superclasses
   * @param theClass the class
   * @param fieldName the field name
   * @param getterName name of setter
   * @param callOnSupers true if superclasses should be looked in for the setter
   * @param throwExceptionIfNotFound will throw runtime exception if not found
   * @return the setter object or null if not found (or exception if param is set)
   */
  public static Method getterHelper(Class theClass, String fieldName, String getterName, 
      boolean callOnSupers, boolean throwExceptionIfNotFound) {
    Method[] methods = retrieveDeclaredMethods(theClass);
    if (methods != null) {
      for (Method method : methods) {
        if (equals(getterName, method.getName()) && isGetter(method)) {
          return method;
        }
      }
    }
    //if method not found
    //if traversing up, and not Object, and not instance method
    if (callOnSupers && !theClass.equals(Object.class)) {
      return getterHelper(theClass.getSuperclass(), fieldName, getterName, 
          callOnSupers, throwExceptionIfNotFound);
    }
    //maybe throw an exception
    if (throwExceptionIfNotFound) {
      throw new RuntimeException("Cant find getter: "
          + getterName + ", in: " + theClass
          + ", callOnSupers: " + callOnSupers);
    }
    return null;
  }

  /**
   * generate getFoo from foo
   * @param propertyName the property name such as "foo" for which to generate method name "getFoo"
   * @return the getter method name
   */
  public static String getterNameFromPropertyName(String propertyName) {
    return "get" + capitalize(propertyName);
  }

  /**
   * get all getters from a class, including superclasses (if specified) (up to and including the specified superclass).  
   * ignore a certain marker annotation, or only include it.
   * Dont get static or final getters, and get getters of all types
   * @param theClass to look for fields in
   * @param superclassToStopAt to go up to or null to go up to Object
   * @param markerAnnotation if this is not null, then if the field has this annotation, then do not
   * include in list (if includeAnnotation is false)
   * @param includeAnnotation true if the attribute should be included if annotation is present, false if exclude
   * @return the set of field names or empty set if none
   */
  @SuppressWarnings("unchecked")
  public static Set<Method> getters(Class theClass, Class superclassToStopAt,
      Class<? extends Annotation> markerAnnotation, Boolean includeAnnotation) {
    return gettersHelper(theClass, superclassToStopAt, null, true, 
        markerAnnotation, includeAnnotation);
  }

  /**
   * get all getters from a class, including superclasses (if specified)
   * @param theClass to look for fields in
   * @param superclassToStopAt to go up to or null to go up to Object
   * @param fieldType is the type of the field to get
   * @param includeSuperclassToStopAt if we should include the superclass
   * @param markerAnnotation if this is not null, then if the field has this annotation, then do not
   * include in list (if includeAnnotation is false)
   * @param includeAnnotation true if the attribute should be included if annotation is present, false if exclude
   * @return the set of fields (wont return null)
   */
  @SuppressWarnings("unchecked")
  static Set<Method> gettersHelper(Class theClass, Class superclassToStopAt, Class<?> fieldType,
      boolean includeSuperclassToStopAt, 
      Class<? extends Annotation> markerAnnotation, Boolean includeAnnotation) {
    //MAKE SURE IF ANY MORE PARAMS ARE ADDED, THE CACHE KEY IS CHANGED!
    
    Set<Method> getterSet = null;
    String cacheKey = theClass + CACHE_SEPARATOR + superclassToStopAt + CACHE_SEPARATOR + fieldType + CACHE_SEPARATOR
      + includeSuperclassToStopAt + CACHE_SEPARATOR + markerAnnotation + CACHE_SEPARATOR + includeAnnotation;
    getterSet = getterSetCache().get(cacheKey);
    if (getterSet != null) {
      return getterSet;
    }
    
    getterSet = new LinkedHashSet<Method>();
    gettersHelper(theClass, superclassToStopAt, fieldType, includeSuperclassToStopAt, 
        markerAnnotation, getterSet, includeAnnotation);
  
    //add to cache
    getterSetCache().put(cacheKey, getterSet);
    
    return getterSet;
    
  }

  /**
   * get all getters from a class, including superclasses (if specified)
   * @param theClass to look for fields in
   * @param superclassToStopAt to go up to or null to go up to Object
   * @param propertyType is the type of the field to get
   * @param includeSuperclassToStopAt if we should include the superclass
   * @param markerAnnotation if this is not null, then if the field has this annotation, then do not
   * include in list
   * @param getterSet set to add fields to
   * @param includeAnnotation if include or exclude
   */
  @SuppressWarnings("unchecked")
  private static void gettersHelper(Class theClass, Class superclassToStopAt, Class<?> propertyType,
      boolean includeSuperclassToStopAt,  
      Class<? extends Annotation> markerAnnotation, Set<Method> getterSet, Boolean includeAnnotation) {

    Method[] methods = retrieveDeclaredMethods(theClass);
    if (length(methods) != 0) {
      for (Method method: methods) {
        //must be a getter
        if (!isGetter(method)) {
          continue;
        }
        //if checking for annotation
        if (markerAnnotation != null
            && (includeAnnotation != method.isAnnotationPresent(markerAnnotation))) {
          continue;
        }
        //if checking for type, and not right type, continue
        if (propertyType != null && !propertyType.isAssignableFrom(method.getReturnType())) {
          continue;
        }
        
        //go for it
        getterSet.add(method);
      }
    }
    //see if done recursing (if superclassToStopAt is null, then stop at Object
    if (theClass.equals(superclassToStopAt) || theClass.equals(Object.class)) {
      return;
    }
    Class superclass = theClass.getSuperclass();
    if (!includeSuperclassToStopAt && superclass.equals(superclassToStopAt)) {
      return;
    }
    //recurse
    gettersHelper(superclass, superclassToStopAt, propertyType, 
        includeSuperclassToStopAt, markerAnnotation, getterSet,
        includeAnnotation);
  }

  /**
   * if the method name starts with get, and takes no args, and returns something, 
   * then getter
   * @param method the method to check for "getter" semantics, such as starting with "get" or "is"
   * @return true if method name starts with "get" or "is", is not static, is not void return type, and does not take arguments
   */
  public static boolean isGetter(Method method) {
    
    //must start with get
    String methodName = method.getName();
    if (!methodName.startsWith("get") && !methodName.startsWith("is")) {
      return false;
    }
  
    //must not be void
    if (method.getReturnType() == Void.TYPE) {
      return false;
    }
    
    //must not take args
    if (length(method.getParameterTypes()) != 0) {
      return false;
    }
    
    //must not be static
    if (Modifier.isStatic(method.getModifiers())) {
      return false;
    }
    
    return true;
  }

  /**
   * assign data to a setter.  Will find the field in superclasses, will typecast, 
   * and will override security (private, protected, etc)
   * @param invokeOn to call on or null for static
   * @param fieldName method name to call
   * @param dataToAssign data  
   * @param typeCast will typecast if true
   * @throws RuntimeException if not there
   */
  public static void assignSetter(Object invokeOn, 
      String fieldName, Object dataToAssign, boolean typeCast) {
    Class invokeOnClass = invokeOn.getClass();
    try {
      Method setter = setter(invokeOnClass, fieldName, true, true);
      setter.setAccessible(true);
      if (typeCast) {
        dataToAssign = typeCast(dataToAssign, setter.getParameterTypes()[0]);
      }
      setter.invoke(invokeOn, new Object[]{dataToAssign});
    } catch (Exception e) {
      throw new RuntimeException("Problem assigning setter: " + fieldName
          + " on class: " + invokeOnClass + ", type of data is: " + className(dataToAssign), e);
    }
  }

  /**
   * Test for setter method.
   * @param method the method to test for being a setter
   * @return true if the method starts with "set", has a void return type,
   *         is not static, and takes only one argument.
   */
  public static boolean isSetter(Method method) {
    
    //must start with set
    if (!method.getName().startsWith("set")) {
      return false;
    }
  
    //must be void
    if (method.getReturnType() != Void.TYPE) {
      return false;
    }
    
    //must take one arg
    if (length(method.getParameterTypes()) != 1) {
      return false;
    }
    
    //must not be static
    if (Modifier.isStatic(method.getModifiers())) {
      return false;
    }
    
    return true;
  }

  /**
   * get a setter method object for a class, potentially in superclasses
   * @param theClass the class
   * @param fieldName the field name
   * @param callOnSupers true if superclasses should be looked in for the setter
   * @param throwExceptionIfNotFound will throw runtime exception if not found
   * @return the setter object or null if not found (or exception if param is set)
   */
  public static Method setter(Class theClass, String fieldName, boolean callOnSupers, 
      boolean throwExceptionIfNotFound) {
    String setterName = setterNameFromPropertyName(fieldName);
    return setterHelper(theClass, fieldName, setterName, callOnSupers, throwExceptionIfNotFound);
  }

  /**
   * get a setter method object for a class, potentially in superclasses
   * @param theClass the class
   * @param fieldName the field name 
   * @param setterName name of setter
   * @param callOnSupers true if superclasses should be looked in for the setter
   * @param throwExceptionIfNotFound will throw runtime exception if not found
   * @return the setter object or null if not found (or exception if param is set)
   */
  public static Method setterHelper(Class theClass, String fieldName, String setterName, 
      boolean callOnSupers, boolean throwExceptionIfNotFound) {
    Method[] methods = retrieveDeclaredMethods(theClass);
    if (methods != null) {
      for (Method method : methods) {
        if (equals(setterName, method.getName()) && isSetter(method)) {
          return method;
        }
      }
    }
    //if method not found
    //if traversing up, and not Object, and not instance method
    if (callOnSupers && !theClass.equals(Object.class)) {
      return setterHelper(theClass.getSuperclass(), fieldName, setterName, 
          callOnSupers, throwExceptionIfNotFound);
    }
    //maybe throw an exception
    if (throwExceptionIfNotFound) {
      throw new RuntimeException("Cant find setter: "
          + setterName + ", in: " + theClass
          + ", callOnSupers: " + callOnSupers);
    }
    return null;
  }

  /**
   * generate setFoo from foo
   * @param propertyName the property such as "foo"
   * @return the setter method name such as "setFoo" 
   */
  public static String setterNameFromPropertyName(String propertyName) {
    return "set" + capitalize(propertyName);
  }

  /**
   * get all setters from a class, including superclasses (if specified)
   * @param theClass to look for fields in
   * @param superclassToStopAt to go up to or null to go up to Object
   * @param fieldType is the type of the field to get
   * @param includeSuperclassToStopAt if we should include the superclass
   * @param markerAnnotation if this is not null, then if the field has this annotation, then do not
   * include in list (if includeAnnotation is false)
   * @param includeAnnotation true if the attribute should be included if annotation is present, false if exclude
   * @return the set of fields (wont return null)
   */
  @SuppressWarnings("unchecked")
  public static Set<Method> setters(Class theClass, Class superclassToStopAt, Class<?> fieldType,
      boolean includeSuperclassToStopAt, 
      Class<? extends Annotation> markerAnnotation, boolean includeAnnotation) {
    return settersHelper(theClass, superclassToStopAt, fieldType, 
        includeSuperclassToStopAt, markerAnnotation, includeAnnotation);
  }

  /**
   * get all setters from a class, including superclasses (if specified)
   * @param theClass to look for fields in
   * @param superclassToStopAt to go up to or null to go up to Object
   * @param fieldType is the type of the field to get
   * @param includeSuperclassToStopAt if we should include the superclass
   * @param markerAnnotation if this is not null, then if the field has this annotation, then do not
   * include in list (if includeAnnotation is false)
   * @param includeAnnotation true if the attribute should be included if annotation is present, false if exclude
   * @return the set of fields (wont return null)
   */
  @SuppressWarnings("unchecked")
  static Set<Method> settersHelper(Class theClass, Class superclassToStopAt, Class<?> fieldType,
      boolean includeSuperclassToStopAt, 
      Class<? extends Annotation> markerAnnotation, boolean includeAnnotation) {
    //MAKE SURE IF ANY MORE PARAMS ARE ADDED, THE CACHE KEY IS CHANGED!
    
    Set<Method> setterSet = null;
    String cacheKey = theClass + CACHE_SEPARATOR + superclassToStopAt + CACHE_SEPARATOR + fieldType + CACHE_SEPARATOR
      + includeSuperclassToStopAt + CACHE_SEPARATOR + markerAnnotation + CACHE_SEPARATOR + includeAnnotation;
    setterSet = setterSetCache().get(cacheKey);
    if (setterSet != null) {
      return setterSet;
    }
    
    setterSet = new LinkedHashSet<Method>();
    settersHelper(theClass, superclassToStopAt, fieldType, includeSuperclassToStopAt, 
        markerAnnotation, setterSet, includeAnnotation);
  
    //add to cache
    setterSetCache().put(cacheKey, setterSet);
    
    return setterSet;
    
  }

  /**
   * get all setters from a class, including superclasses (if specified)
   * @param theClass to look for fields in
   * @param superclassToStopAt to go up to or null to go up to Object
   * @param propertyType is the type of the field to get
   * @param includeSuperclassToStopAt if we should include the superclass
   * @param markerAnnotation if this is not null, then if the field has this annotation, then do not
   * include in list
   * @param setterSet set to add fields to
   * @param includeAnnotation if include or exclude (or null if not looking for annotations)
   */
  @SuppressWarnings("unchecked")
  private static void settersHelper(Class theClass, Class superclassToStopAt, Class<?> propertyType,
      boolean includeSuperclassToStopAt,  
      Class<? extends Annotation> markerAnnotation, Set<Method> setterSet, Boolean includeAnnotation) {

    Method[] methods = retrieveDeclaredMethods(theClass);
    if (length(methods) != 0) {
      for (Method method: methods) {
        //must be a getter
        if (!isSetter(method)) {
          continue;
        }
        //if checking for annotation
        if (markerAnnotation != null
            && (includeAnnotation != method.isAnnotationPresent(markerAnnotation))) {
          continue;
        }
        //if checking for type, and not right type, continue
        if (propertyType != null && !propertyType.isAssignableFrom(method.getParameterTypes()[0])) {
          continue;
        }
        
        //go for it
        setterSet.add(method);
      }
    }
    //see if done recursing (if superclassToStopAt is null, then stop at Object
    if (theClass.equals(superclassToStopAt) || theClass.equals(Object.class)) {
      return;
    }
    Class superclass = theClass.getSuperclass();
    if (!includeSuperclassToStopAt && superclass.equals(superclassToStopAt)) {
      return;
    }
    //recurse
    settersHelper(superclass, superclassToStopAt, propertyType, 
        includeSuperclassToStopAt, markerAnnotation, setterSet,
        includeAnnotation);
  }

  /**
   * If this is a getter or setter, then get the property name
   * @param method a method with name like "getFoo," "setFoo," or "isFoo."
   * @return the property name inferred from the method name.  For example, "getFoo" returns "foo."
   */
  public static String propertyName(Method method) {
    String methodName = method.getName();
    boolean isGetter = methodName.startsWith("get");
    boolean isSetter = methodName.startsWith("set");
    boolean isIsser = methodName.startsWith("is");
    int expectedLength = isIsser ? 2 : 3; 
    int length = methodName.length();
    if ((!(isGetter || isSetter || isIsser)) || (length <= expectedLength)) {
      throw new RuntimeException("Not a getter or setter: " + methodName);
    }
    char fourthCharLower = Character.toLowerCase(methodName.charAt(expectedLength));
    //if size 4, then return the string
    if (length == expectedLength +1) {
      return Character.toString(fourthCharLower);
    }
    //return the lower appended with the rest
    return fourthCharLower + methodName.substring(expectedLength+1, length);
  }

  /**
   * use reflection to get a property type based on getter or setter or field
   * @param theClass the class
   * @param propertyName the property name
   * @return the property type
   */
  public static Class propertyType(Class theClass, String propertyName) {
    Method method = getter(theClass, propertyName, true, false);
    if (method != null) {
      return method.getReturnType();
    }
    //use setter
    method = setter(theClass, propertyName, true, false);
    if (method != null) {
      return method.getParameterTypes()[0];
    }
    //no setter or getter, use field
    Field field = field(theClass, propertyName, true, true);
    return field.getType();
  }

  /**
   * If necessary, convert an object to another type.  if type is Object.class, just return the input.
   * Do not convert null to an empty primitive
   * @param <T> is template type
   * @param value The object to cast
   * @param theClass the type of class to cast to
   * @return the object of that instance converted into something else
   */
  public static <T> T typeCast(Object value, Class<T> theClass) {
    //default behavior is not to convert null to empty primitive
    return typeCast(value, theClass, false, false);
  }

  /**
   * <pre>
   * make a new file in the name prefix dir.  If parent dir name is c:\temp
   * and namePrefix is grouperDdl and nameSuffix is sql, then the file will be:
   * 
   * c:\temp\grouperDdl_20080721_13_45_43_123.sql
   *  
   * If the file exists, it will make a new filename, and create the empty file, and return it
   * </pre>
   *  
   * @param parentDirName can be blank for current dir
   * @param namePrefix the part before the date part
   * @param nameSuffix the last part of file name (can contain dot or will be the extension
   * @param createFile true to create the file
   * @return the created file
   */
  public static File newFileUniqueName(String parentDirName, String namePrefix, String nameSuffix, boolean createFile) {
    DateFormat fileNameFormat = new SimpleDateFormat("yyyyMMdd_HH_mm_ss_SSS");
    if (!isBlank(parentDirName)) {

      if (!parentDirName.endsWith("/") && !parentDirName.endsWith("\\")) {
        parentDirName += File.separator;
      }
      
      //make sure it exists and is a dir
      File parentDir = new File(parentDirName);
      if (!parentDir.exists()) {
        if (!parentDir.mkdirs()) {
          throw new RuntimeException("Cant make dir: " + parentDir.getAbsolutePath());
        }
      } else {
        if (!parentDir.isDirectory()) {
          throw new RuntimeException("Parent dir is not a directory: " + parentDir.getAbsolutePath());
        } 
      }
      
    } else {
      //make it empty string so it will concatenate well
      parentDirName = "";
    }
    //make sure suffix has a dot in it
    if (!nameSuffix.contains(".")) {
      nameSuffix = "." + nameSuffix;
    }
    
    String fileName = parentDirName + namePrefix + "_" + fileNameFormat.format(new Date()) + nameSuffix;
    int dotLocation = fileName.lastIndexOf('.');
    String fileNamePre = fileName.substring(0,dotLocation);
    String fileNamePost = fileName.substring(dotLocation);
    File theFile = new File(fileName);

    int i;
    
    for (i=0;i<1000;i++) {
      
      if (!theFile.exists()) {
        break;
      }
      
      fileName = fileNamePre + "_" + i + fileNamePost;
      theFile = new File(fileName);
      
    }
    
    if (i>=1000) {
      throw new RuntimeException("Cant find filename to create: " + fileName);
    }
    
    if (createFile) {
      try {
        if (!theFile.createNewFile()) {
          throw new RuntimeException("Cant create file, it returned false");
        }
      } catch (Exception e) {
        throw new RuntimeException("Cant create file: " + fileName + ", make sure " +
            "permissions and such are ok, or change file location in grouper.properties if applicable", e);
      }
    }
    return theFile;
  }
  
  /**
   * <pre>
   * Convert an object to a java.util.Date.  allows, dates, null, blank, 
   * yyyymmdd or yyyymmdd hh24:mm:ss
   * or yyyy/MM/dd HH:mm:ss.SSS
   * </pre>
   * @param inputObject
   *          is the String or Date to convert
   * 
   * @return the Date
   */
  public static Date dateValue(Object inputObject) {
    if (inputObject == null) {
      return null;
    } 

    if (inputObject instanceof java.util.Date) {
      return (Date)inputObject;
    }

    if (inputObject instanceof String) {
      String input = (String)inputObject;
      //trim and handle null and empty
      if (isBlank(input)) {
        return null;
      }

      try {
        if (input.length() == 8) {
          
          return dateFormat().parse(input);
        }
        if (!contains(input, '.')) {
          if (contains(input, '/')) {
            return dateMinutesSecondsFormat.parse(input);
          }
          //else no slash
          return dateMinutesSecondsNoSlashFormat.parse(input);
        }
        if (contains(input, '/')) {
          //see if the period is 6 back
          int lastDotIndex = input.lastIndexOf('.');
          if (lastDotIndex == input.length() - 7) {
            String nonNanoInput = input.substring(0,input.length()-3);
            Date date = timestampFormat.parse(nonNanoInput);
            //get the last 3
            String lastThree = input.substring(input.length()-3,input.length());
            int lastThreeInt = Integer.parseInt(lastThree);
            Timestamp timestamp = new Timestamp(date.getTime());
            timestamp.setNanos(timestamp.getNanos() + (lastThreeInt * 1000));
            return timestamp;
          }
          return timestampFormat.parse(input);
        }
        //else no slash
        return timestampNoSlashFormat.parse(input);
      } catch (ParseException pe) {
        throw new RuntimeException(errorStart + toStringForLog(input));
      }
    }
    
    throw new RuntimeException("Cannot convert Object to date : " + toStringForLog(inputObject));
  }

  /**
   * See if the input is null or if string, if it is empty or blank (whitespace)
   * @param input object to test for null or String to check for blank
   * @return true if null or blank string
   */
  public static boolean isBlank(Object input) {
    if (null == input) {
      return true;
    }
    return (input instanceof String && isBlank((String)input));
  }

  /**
   * If necessary, convert an object to another type.  if type is Object.class, just return the input
   * @param <T> is the type to return
   * @param value The object to cast
   * @param theClass The desired cast class type
   * @param convertNullToDefaultPrimitive if the value is null, and theClass is primitive, should we
   * convert the null to a primitive default value
   * @param useNewInstanceHooks if theClass is not recognized, then honor the string "null", "newInstance",
   * or get a constructor with one param, and call it
   * @return the object of that instance converted into something else
   */
  @SuppressWarnings({ "unchecked", "cast" })
  public static <T> T typeCast(Object value, Class<T> theClass, 
      boolean convertNullToDefaultPrimitive, boolean useNewInstanceHooks) {
    
    if (Object.class.equals(theClass)) {
      return (T)value;
    }
    
    if (value==null) {
      if (convertNullToDefaultPrimitive && theClass.isPrimitive()) {
        if ( theClass == boolean.class ) {
          return (T)Boolean.FALSE;
        }
        if ( theClass == char.class ) {
          return (T)(Object)0;
        }
        //convert 0 to the type
        return typeCast(0, theClass, false, false);
      }
      return null;
    }
  
    if (theClass.isInstance(value)) {
      return (T)value;
    }
    
    //if array, get the base class
    if (theClass.isArray() && theClass.getComponentType() != null) {
      theClass = (Class<T>)theClass.getComponentType();
    }
    Object resultValue = null;
    //loop through and see the primitive types etc
    if (theClass.equals(Date.class)) {
      resultValue = dateValue(value);
    } else if (theClass.equals(String.class)) {
      resultValue = stringValue(value);
    } else if (theClass.equals(Timestamp.class)) {
      resultValue = toTimestamp(value);
    } else if (theClass.equals(Boolean.class) || theClass.equals(boolean.class)) {
      resultValue = booleanObjectValue(value);
    } else if (theClass.equals(Integer.class) || theClass.equals(int.class)) {
      resultValue = intObjectValue(value, true);
    } else if (theClass.equals(Double.class) || theClass.equals(double.class)) {
      resultValue = doubleObjectValue(value, true);
    } else if (theClass.equals(Float.class) || theClass.equals(float.class)) {
      resultValue = floatObjectValue(value, true);
    } else if (theClass.equals(Long.class) || theClass.equals(long.class)) {
      resultValue = longObjectValue(value, true);
    } else if (theClass.equals(Byte.class) || theClass.equals(byte.class)) {
      resultValue = byteObjectValue(value);
    } else if (theClass.equals(Character.class) || theClass.equals(char.class)) {
      resultValue = charObjectValue(value);
    } else if (theClass.equals(Short.class) || theClass.equals(short.class)) {
      resultValue = shortObjectValue(value);
    } else if ( theClass.isEnum() && (value instanceof String) ) {
      resultValue = Enum.valueOf((Class)theClass, (String) value);
    } else if ( theClass.equals(Class.class) && (value instanceof String) ) {
      resultValue = forName((String)value);
    } else if (useNewInstanceHooks && value instanceof String) {
      String stringValue = (String)value;
      if ( equals("null", stringValue)) {
        resultValue = null;
      } else if (equals("newInstance", stringValue)) {
        resultValue = newInstance(theClass);
      } else { // instantiate using string
        //note, we could typecast this to fit whatever is there... right now this is used for annotation
        try {
          Constructor constructor = theClass.getConstructor(new Class[] {String.class} );
          resultValue = constructor.newInstance(new Object[] {stringValue} );            
        } catch (Exception e) {
          throw new RuntimeException("Cant find constructor with string for class: " + theClass);
        }
      }
    } else {
      throw new RuntimeException("Cannot convert from type: " + value.getClass() + " to type: " + theClass);
    }
  
    return (T)resultValue;
  }
  
  /**
   * see if a class is a scalar (not bean, not array or list, etc)
   * @param type the type to check
   * @return true if scalar
   */
  public static boolean isScalar(Class<?> type) {
    
    if (type.isArray()) {
      return false;
    }
    
    //definitely all primitives
    if (type.isPrimitive()) {
      return true;
    }
    //Integer, Float, etc
    if (Number.class.isAssignableFrom(type)) {
      return true;
    }
    //Date, Timestamp
    if (Date.class.isAssignableFrom(type)) {
      return true;
    }
    if (Character.class.equals(type)) {
      return true;
    }
    //handles strings and string builders
    if (CharSequence.class.equals(type) || CharSequence.class.isAssignableFrom(type)) {
      return true;
    }
    if (Class.class == type || Boolean.class == type || type.isEnum()) {
      return true;
    }
    //appears not to be a scalar
    return false;
  }
  
  
  /**
   * <pre>
   * Convert a string or object to a timestamp (could be string, date, timestamp, etc)
   * yyyymmdd
   * or
   * yyyy/MM/dd HH:mm:ss
   * or
   * yyyy/MM/dd HH:mm:ss.SSS
   * or
   * yyyy/MM/dd HH:mm:ss.SSSSSS
   * 
   * </pre>
   * 
   * @param input a String, java.sql.Timestamp, or java.sql.Date
   * @return the timestamp 
   * @throws RuntimeException if invalid format
   */
  public static Timestamp toTimestamp(Object input) {

    if (null == input) {
      return null;
    } else if (input instanceof java.sql.Timestamp) {
      return (Timestamp) input;
    } else if (input instanceof String) {
      return stringToTimestamp((String) input);
    } else if (input instanceof Date) {
      return new Timestamp(((Date)input).getTime());
    } else if (input instanceof java.sql.Date) {
      return new Timestamp(((java.sql.Date)input).getTime());
    } else {
      throw new RuntimeException("Cannot convert Object to timestamp : " + input);
    }

  }

  /**
   * convert an object to a string
   * 
   * @param input
   *          is the object to convert, such as a Timestamp, Date, or Number.
   * 
   * @return the String conversion of the object
   */
  public static String stringValue(Object input) {
    //this isnt needed
    if (input == null) {
      return (String) input;
    }

    if (input instanceof Timestamp) {
      //convert to yyyy/MM/dd HH:mm:ss.SSS
      return timestampToString((Timestamp) input);
    }

    if (input instanceof Date) {
      //convert to yyyymmdd
      return stringValue((Date) input);
    }

    if (input instanceof Number) {
      DecimalFormat decimalFormat = new DecimalFormat(
          "###################.###############");
      return decimalFormat.format(((Number) input).doubleValue());

    }

    return input.toString();
  }

  /**
   * Convert a timestamp into a string: yyyy/MM/dd HH:mm:ss.SSS
   * @param timestamp Date object to be formatted as a string
   * @return the string representation
   */
  public synchronized static String timestampToString(Date timestamp) {
    if (timestamp == null) {
      return null;
    }
    return timestampFormat.format(timestamp);
  }

  /**
   * get the timestamp format for this thread
   * if you call this make sure to synchronize on FastDateUtils.class
   * @return the timestamp format
   */
  synchronized static SimpleDateFormat dateFormat() {
    return dateFormat;
  }

  /**
   * convert a date to the standard string yyyymmdd
   * @param date the date to format
   * @return the string value
   */
  public static String stringValue(java.util.Date date) {
    synchronized (ConfigPropertiesCascadeCommonUtils.class) {
      if (date == null) {
        return null;
      }
  
      String theString = dateFormat().format(date);
  
      return theString;
    }
  }

  /**
   * convert a string to timestamp based on the following formats:
   * <pre>
   * yyyyMMdd
   * yyyy/MM/dd HH:mm:ss
   * yyyy/MM/dd HH:mm:ss.SSS
   * yyyy/MM/dd HH:mm:ss.SSSSSS
   * </pre>
   * @param input the string to be converted into a Timestamp
   * @return the timestamp object
   * @see #stringToTimestampHelper(String)
   */
  public static Timestamp stringToTimestamp(String input) {
    Date date = stringToTimestampHelper(input);
    if (date == null) {
      return null;
    }
    //maybe already a timestamp
    if (date instanceof Timestamp) {
      return (Timestamp)date; 
    }
    return new Timestamp(date.getTime());
  }

  /**
   * return a date based on input, null safe.  Allow any of the three 
   * formats:
   * <pre>
   * yyyyMMdd
   * yyyy/MM/dd HH:mm:ss
   * yyyy/MM/dd HH:mm:ss.SSS
   * yyyy/MM/dd HH:mm:ss.SSSSSS
   * </pre>
   * 
   * @param input The string to be converted into a Date
   * @return a Date parsed from the input string
   */
  synchronized static Date stringToTimestampHelper(String input) {
    //trim and handle null and empty
    if (isBlank(input)) {
      return null;
    }
  
    try {
      //convert mainframe
      if (equals("99999999", input)
          || equals("999999", input)) {
        input = "20991231";
      }
      if (input.length() == 8) {
        
        return dateFormat().parse(input);
      }
      if (!contains(input, '.')) {
        if (contains(input, '/')) {
          return dateMinutesSecondsFormat.parse(input);
        }
        //else no slash
        return dateMinutesSecondsNoSlashFormat.parse(input);
      }
      if (contains(input, '/')) {
        //see if the period is 6 back
        int lastDotIndex = input.lastIndexOf('.');
        if (lastDotIndex == input.length() - 7) {
          String nonNanoInput = input.substring(0,input.length()-3);
          Date date = timestampFormat.parse(nonNanoInput);
          //get the last 3
          String lastThree = input.substring(input.length()-3,input.length());
          int lastThreeInt = Integer.parseInt(lastThree);
          Timestamp timestamp = new Timestamp(date.getTime());
          timestamp.setNanos(timestamp.getNanos() + (lastThreeInt * 1000));
          return timestamp;
        }
        return timestampFormat.parse(input);
      }
      //else no slash
      return timestampNoSlashFormat.parse(input);
    } catch (ParseException pe) {
      throw new RuntimeException(errorStart + input);
    }
  }

  /**
   * start of error parsing messages
   */
  private static final String errorStart = "Invalid timestamp, please use any of the formats: "
    + DATE_FORMAT + ", " + TIMESTAMP_FORMAT 
    + ", " + DATE_MINUTES_SECONDS_FORMAT + ": ";

  /**
   * Convert an object to a BigDecimal, allow nulls
   * @param input the object to cast, or null
   * @return the BigDecimal value of the input object
   * @see java.math.BigDecimal#valueOf(double)
   */
  public static BigDecimal bigDecimalObjectValue(Object input) {
    if (input instanceof BigDecimal) {
      return (BigDecimal)input;
    }
    if (isBlank(input)) {
      return null;
    }
    return BigDecimal.valueOf(doubleValue(input));
  }

  /**
   * Convert an object to a Byte, allow nulls
   * @param input the object to cast, or null
   * @return the Byte object value
   */
  public static Byte byteObjectValue(Object input) {
    if (input instanceof Byte) {
      return (Byte)input;
    }
    if (isBlank(input)) {
      return null;
    }
    return Byte.valueOf(byteValue(input));
  }

  /**
   * convert an object to a byte
   * @param input the object to convert to a byte
   * @return the byte value of the given number, or the parsed byte of the string
   */
  public static byte byteValue(Object input) {
    if (input instanceof String) {
      String string = (String)input;
      return Byte.parseByte(string);
    }
    if (input instanceof Number) {
      return ((Number)input).byteValue();
    }
    throw new RuntimeException("Cannot convert to byte: " + className(input));
  }

  /**
   * get the Double value of an object
   * 
   * @param input
   *          is a number or String
   * @param allowNullBlank used to default to false, if true, return null if nul inputted 
   * 
   * @return the Double equivalent
   */
  public static Double doubleObjectValue(Object input, boolean allowNullBlank) {
  
    if (input instanceof Double) {
      return (Double) input;
    } 
    
    if (allowNullBlank && isBlank(input)) {
      return null;
    }
    
    return Double.valueOf(doubleValue(input));
  }

  /**
   * get the double value of an object
   * 
   * @param input
   *          is a number or String
   * 
   * @return the double equivalent
   */
  public static double doubleValue(Object input) {
    if (input instanceof String) {
      String string = (String)input;
      return Double.parseDouble(string);
    }
    if (input instanceof Number) {
      return ((Number)input).doubleValue();
    }
    throw new RuntimeException("Cannot convert to double: "  + className(input));
  }

  /**
   * get the double value of an object, do not throw an 
   * exception if there is an
   * error
   * 
   * @param input
   *          is a number or String
   * 
   * @return the double equivalent
   */
  public static double doubleValueNoError(Object input) {
    if (input == null || (input instanceof String 
        && isBlank((String)input))) {
      return NOT_FOUND;
    }
  
    try {
      return doubleValue(input);
    } catch (Exception e) {
      //no need to log here
    }
  
    return NOT_FOUND;
  }

  /**
   * get the Float value of an object
   * 
   * @param input
   *          is a number or String
   * @param allowNullBlank true if allow null or blank
   * 
   * @return the Float equivalent
   */
  public static Float floatObjectValue(Object input, boolean allowNullBlank) {
  
    if (input instanceof Float) {
      return (Float) input;
    } 
  
    if (allowNullBlank && isBlank(input)) {
      return null;
    }
    return Float.valueOf(floatValue(input));
  }

  /**
   * get the float value of an object
   * 
   * @param input
   *          is a number or String
   * 
   * @return the float equivalent
   */
  public static float floatValue(Object input) {
    if (input instanceof String) {
      String string = (String)input;
      return Float.parseFloat(string);
    }
    if (input instanceof Number) {
      return ((Number)input).floatValue();
    }
    throw new RuntimeException("Cannot convert to float: " + className(input));
  }

  /**
   * get the float value of an object, do not throw an exception if there is an
   * error
   * 
   * @param input
   *          is a number or String
   * 
   * @return the float equivalent
   */
  public static float floatValueNoError(Object input) {
    if (input == null || (input instanceof String 
        && isBlank((String)input))) {
      return NOT_FOUND;
    }
    try {
      return floatValue(input);
    } catch (Exception e) {
      e.printStackTrace();
    }
  
    return NOT_FOUND;
  }

  /**
   * get the Integer value of an object
   * 
   * @param input
   *          is a number or String
   * @param allowNullBlank true if convert null or blank to null
   * 
   * @return the Integer equivalent
   */
  public static Integer intObjectValue(Object input, boolean allowNullBlank) {
  
    if (input instanceof Integer) {
      return (Integer) input;
    } 
  
    if (allowNullBlank && isBlank(input)) {
      return null;
    }
    
    return Integer.valueOf(intValue(input));
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
   * convert an object to a int
   * @param input the object to convert to an int
   * @param valueIfNull is if the input is null or empty, return this value
   * @return the integer primitive represented by the object
   */
  public static int intValue(Object input, int valueIfNull) {
    if (input == null || "".equals(input)) {
      return valueIfNull;
    }
    return intObjectValue(input, false);
  }

  /**
   * get the int value of an object, do not throw an exception if there is an
   * error
   * 
   * @param input
   *          is a number or String
   * 
   * @return the int equivalent
   */
  public static int intValueNoError(Object input) {
    if (input == null || (input instanceof String 
        && isBlank((String)input))) {
      return NOT_FOUND;
    }
    try {
      return intValue(input);
    } catch (Exception e) {
      //no need to log here
    }
  
    return NOT_FOUND;
  }

  /** special number when a number is not found */
  public static final int NOT_FOUND = -999999999;

  /**
   * The name says it all.
   */
  public static final int DEFAULT_BUFFER_SIZE = 1024 * 4;

  /**
   * get the Long value of an object
   * 
   * @param input
   *          is a number or String
   * @param allowNullBlank true if null or blank converts to null
   * 
   * @return the Long equivalent
   */
  public static Long longObjectValue(Object input, boolean allowNullBlank) {
  
    if (input instanceof Long) {
      return (Long) input;
    } 
  
    if (allowNullBlank && isBlank(input)) {
      return null;
    } 
    
    return Long.valueOf(longValue(input));
  }

  /**
   * convert an object to a long
   * @param input String or Number
   * @return the number
   */
  public static long longValue(Object input) {
    if (input instanceof String) {
      String string = (String)input;
      return Long.parseLong(string);
    }
    if (input instanceof Number) {
      return ((Number)input).longValue();
    }
    throw new RuntimeException("Cannot convert to long: " + className(input));
  }

  /**
   * convert an object to a long
   * @param input value to convert
   * @param valueIfNull is if the input is null or empty, return this value
   * @return the number
   */
  public static long longValue(Object input, long valueIfNull) {
    if (input == null || "".equals(input)) {
      return valueIfNull;
    }
    return longObjectValue(input, false);
  }

  /**
   * get the long value of an object, do not throw an exception if there is an
   * error
   * 
   * @param input
   *          is a number or String
   * 
   * @return the long equivalent
   */
  public static long longValueNoError(Object input) {
    if (input == null || (input instanceof String 
        && isBlank((String)input))) {
      return NOT_FOUND;
    }
    try {
      return longValue(input);
    } catch (Exception e) {
      //no need to log here
    }
  
    return NOT_FOUND;
  }

  /**
   * get the Short value of an object.  converts null or blank to null
   * 
   * @param input
   *          is a number or String
   * 
   * @return the Long equivalent
   */
  public static Short shortObjectValue(Object input) {
  
    if (input instanceof Short) {
      return (Short) input;
    }
  
    if (isBlank(input)) {
      return null;
    } 
    
    return Short.valueOf(shortValue(input));
  }

  /**
   * convert an object to a short
   * @param input String or Number value to convert
   * @return the number
   */
  public static short shortValue(Object input) {
    if (input instanceof String) {
      String string = (String)input;
      return Short.parseShort(string);
    }
    if (input instanceof Number) {
      return ((Number)input).shortValue();
    }
    throw new RuntimeException("Cannot convert to short: " + className(input));
  }

  /**
   * get the Character wrapper value for the input
   * @param input allow null, return null
   * @return the Character object wrapper
   */
  public static Character charObjectValue(Object input) {
    if (input instanceof Character) {
      return (Character) input;
    }
    if (isBlank(input)) {
      return null;
    }
    return new Character(charValue(input));
  }

  /**
   * convert an object to a char
   * @param input Character or String
   * @return the number
   */
  public static char charValue(Object input) {
    if (input instanceof Character) {
      return ((Character) input).charValue();
    }
    //if string length 1, thats ok
    if (input instanceof String) {
      String inputString = (String) input;
      if (inputString.length() == 1) {
        return inputString.charAt(0);
      }
    }
    throw new RuntimeException("Cannot convert to char: "
        + (input == null ? null : (input.getClass() + ", " + input)));
  }

  /**
   * Create the parent directories for a file if they do not already exist
   * @param file the File whose parent directories need creating
   * @see File#mkdirs()
   */
  public static void createParentDirectories(File file) {
    if (!file.getParentFile().exists()) {
      if (!file.getParentFile().mkdirs()) {
        throw new RuntimeException("Could not create directory : " + file.getParentFile());
      }
    }
  }

  /**
   * save a string into a file, file does not have to exist
   * 
   * @param file
   *          is the file to save to
   * @param contents
   *          is the contents of the file
   */
  public static void saveStringIntoFile(File file, String contents) {
    try {
      writeStringToFile(file, contents, "UTF-8");
    } catch (IOException ioe) {
      throw new RuntimeException(ioe);
    }
  }

  /**
   * save a string into a file, file does not have to exist
   * 
   * @param file
   *          is the file to save to
   * @param contents
   *          is the contents of the file
   * @param onlyIfDifferentContents true if only saving due to different contents
   * @param ignoreWhitespace true to ignore whitespace
   * @return true if contents were saved (thus different if param set)
   */
  public static boolean saveStringIntoFile(File file, String contents, 
      boolean onlyIfDifferentContents, boolean ignoreWhitespace) {
    if (onlyIfDifferentContents && file.exists()) {
      String fileContents = readFileIntoString(file);
      String compressedContents = contents;
      if (ignoreWhitespace) {
        compressedContents = replaceWhitespaceWithSpace(compressedContents);
        fileContents = replaceWhitespaceWithSpace(fileContents);
      }
      
      //they are the same, dont worry about it
      if (equals(fileContents, compressedContents)) {
        return false;
      }
  
    }
    saveStringIntoFile(file, contents);
    return true;
  }

  /**
   * <p>
   * Writes data to a file. The file will be created if it does not exist.
   * </p>
   * <p>
   * There is no readFileToString method without encoding parameter because
   * the default encoding can differ between platforms and therefore results
   * in inconsistent results.
   * </p>
   *
   * @param file the file to write.
   * @param data The content to write to the file.
   * @param encoding encoding to use
   * @throws IOException in case of an I/O error
   * @throws UnsupportedEncodingException if the encoding is not supported
   *   by the VM
   */
  public static void writeStringToFile(File file, String data, String encoding)
      throws IOException {
    OutputStream out = new java.io.FileOutputStream(file);
    try {
      out.write(data.getBytes(encoding));
    } finally {
      closeQuietly(out);
    }
  }

  /**
   * @param file
   *          is the file to read into a string
   * 
   * @return String
   */
  public static String readFileIntoString(File file) {
  
    if (file == null) {
      return null;
    }
    try {
      return readFileToString(file, "UTF-8");
    } catch (IOException ioe) {
      throw new RuntimeException(ioe);
    }
  }

  /**
   * @param resourceName is the string resource from classpath to read (e.g. grouper.properties)
   * @param allowNull is true if its ok if the resource is null or if it is not found or blank or whatever.
   * 
   * @return String or null if allowed or RuntimeException if not allowed
   */
  public static String readResourceIntoString(String resourceName, boolean allowNull) {
    if (isBlank(resourceName)) {
      if (allowNull) {
        return null;
      }
      throw new RuntimeException("Resource name is blank");
    }
    URL url = computeUrl(resourceName, allowNull);

    //this is ok
    if (url == null && allowNull) {
      return null;
    }
    
    InputStream inputStream = null;
    StringWriter stringWriter = new StringWriter();
    try {
      inputStream = url.openStream();
      copy(inputStream, stringWriter, "UTF-8");
    } catch (IOException ioe) {
      throw new RuntimeException("Error reading resource: '" + resourceName + "'", ioe);
    } finally {
      closeQuietly(inputStream);
      closeQuietly(stringWriter);
    }
    return stringWriter.toString();
  }

  /**
   * read resource into string
   * @param resourceName the resource name
   * @param classInJar if not null, then look for the jar where this file is, and look in the same dir
   * @return the properties or null if not exist
   */
  public static String readResourceIntoString(String resourceName, Class<?> classInJar) {

    try {
      return readResourceIntoString(resourceName, false);
    } catch (Exception e) {
      //try from jar location
    }
  
    //lets look next to jar
    File jarFile = classInJar == null ? null : jarFile(classInJar);
    File parentDir = jarFile == null ? null : jarFile.getParentFile();
    String fileName = parentDir == null ? null 
        : (stripLastSlashIfExists(fileCanonicalPath(parentDir)) + File.separator + resourceName);
    File configFile = fileName == null ? null 
        : new File(fileName);

    return readFileIntoString(configFile);
  }

  /**
   * <p>
   * Reads the contents of a file into a String.
   * </p>
   * <p>
   * There is no readFileToString method without encoding parameter because
   * the default encoding can differ between platforms and therefore results
   * in inconsistent results.
   * </p>
   *
   * @param file the file to read.
   * @param encoding the encoding to use
   * @return The file contents or null if read failed.
   * @throws IOException in case of an I/O error
   */
  public static String readFileToString(File file, String encoding) throws IOException {
    InputStream in = new java.io.FileInputStream(file);
    try {
      return toString(in, encoding);
    } finally {
      closeQuietly(in);
    }
  }

  /**
   * replace all consecutive whitespace with single space character
   * @param input the input string
   * @return the string with redundant whitespace collapsed
   */
  public static String replaceWhitespaceWithSpace(String input) {
    if (input == null) {
      return input;
    }
    return input.replaceAll("\\s+", " ");
  }

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
   * Unconditionally close an <code>OutputStream</code>.
   * Equivalent to {@link OutputStream#close()}, except any exceptions will be ignored.
   * @param output A (possibly null) OutputStream
   */
  public static void closeQuietly(OutputStream output) {
    if (output == null) {
      return;
    }
  
    try {
      output.close();
    } catch (IOException ioe) {
    }
  }

  /**
   * Unconditionally close an <code>Reader</code>.
   * Equivalent to {@link Reader#close()}, except any exceptions will be ignored.
   *
   * @param input A (possibly null) Reader
   */
  public static void closeQuietly(Reader input) {
    if (input == null) {
      return;
    }
  
    try {
      input.close();
    } catch (IOException ioe) {
    }
  }

  /**
   * close a writer quietly, swallowing IOException
   * @param writer the writer to close
   */
  public static void closeQuietly(Writer writer) {
    if (writer != null) {
      try {
        writer.close();
      } catch (IOException e) {
        //swallow, its ok
      }
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
   * this method takes a long (less than 62) and converts it to a 1 character
   * string (a-z, A-Z, 0-9)
   * 
   * @param theLong
   *          is the long (less than 62) to convert to a 1 character string
   * 
   * @return a one character string
   */
  public static String convertLongToChar(long theLong) {
    if ((theLong < 0) || (theLong >= 62)) {
      throw new RuntimeException("convertLongToChar() "
          + " invalid input (not >=0 && <62: " + theLong);
    } else if (theLong < 26) {
      return "" + (char) ('a' + theLong);
    } else if (theLong < 52) {
      return "" + (char) ('A' + (theLong - 26));
    } else {
      return "" + (char) ('0' + (theLong - 52));
    }
  }

  /**
   * this method takes a long (less than 36) and converts it to a 1 character
   * string (A-Z, 0-9)
   * 
   * @param theLong
   *          is the long (less than 36) to convert to a 1 character string
   * 
   * @return a one character string
   */
  public static String convertLongToCharSmall(long theLong) {
    if ((theLong < 0) || (theLong >= 36)) {
      throw new RuntimeException("convertLongToCharSmall() "
          + " invalid input (not >=0 && <36: " + theLong);
    } else if (theLong < 26) {
      return "" + (char) ('A' + theLong);
    } else {
      return "" + (char) ('0' + (theLong - 26));
    }
  }

  /**
   * convert a long to a string by converting it to base 62 (26 lower, 26 upper,
   * 10 digits)
   * 
   * @param theLong
   *          is the long to convert
   * 
   * @return the String conversion of this
   */
  public static String convertLongToString(long theLong) {
    long quotient = theLong / 62;
    long remainder = theLong % 62;
  
    if (quotient == 0) {
      return convertLongToChar(remainder);
    }
    StringBuffer result = new StringBuffer();
    result.append(convertLongToString(quotient));
    result.append(convertLongToChar(remainder));
  
    return result.toString();
  }

  /**
   * convert a long to a string by converting it to base 36 (26 upper, 10
   * digits)
   * 
   * @param theLong
   *          is the long to convert
   * 
   * @return the String conversion of this
   */
  public static String convertLongToStringSmall(long theLong) {
    long quotient = theLong / 36;
    long remainder = theLong % 36;
  
    if (quotient == 0) {
      return convertLongToCharSmall(remainder);
    }
    StringBuffer result = new StringBuffer();
    result.append(convertLongToStringSmall(quotient));
    result.append(convertLongToCharSmall(remainder));
  
    return result.toString();
  }

  /**
   * increment a character (A-Z then 0-9)
   * 
   * @param theChar The charater to be "incremented"
   * 
   * @return the charcter that follows the input character, wrapping from 'Z' to '0' and '9' to 'A' in the set [A-Z0-9]
   */
  public static char incrementChar(char theChar) {
    if (theChar == 'Z') {
      return '0';
    }
  
    if (theChar == '9') {
      return 'A';
    }
  
    return ++theChar;
  }

  /**
   * Increment a string with A-Z and 0-9 (no lower case so case insensitive apps
   * like windows IE will still work)
   * 
   * @param string  the character array to increment.
   * 
   * @return the incremented character array
   */
  public static char[] incrementStringInt(char[] string) {
    if (string == null) {
      return string;
    }
  
    //loop through the string backwards
    int i = 0;
  
    for (i = string.length - 1; i >= 0; i--) {
      char inc = string[i];
      inc = incrementChar(inc);
      string[i] = inc;
  
      if (inc != 'A') {
        break;
      }
    }
  
    //if we are at 0, then it means we hit AAAAAAA (or more)
    if (i < 0) {
      return ("A" + new String(string)).toCharArray();
    }
  
    return string;
  }

  /**
   * read properties from a resource, don't modify the properties returned since they are cached
   * @param resourceName the resource name
   * @return the properties
   */
  public synchronized static Properties propertiesFromResourceName(String resourceName) {
    return propertiesFromResourceName(resourceName, true, true, null, null);
  }

  /**
   * clear properties cache (e.g. for testing)
   */
  public static void propertiesCacheClear() {
    resourcePropertiesCache.clear();
  }
  
  /**
   * read properties from file
   * @param file the properties file
   * @return properties
   */
  public static Properties propertiesFromFile(File file) {
    Properties properties = new Properties();
    FileInputStream fileInputStream = null;
    try {
      
      fileInputStream = new FileInputStream(file);
      properties.load(fileInputStream);
      
    } catch (IOException ioe) {
      throw new RuntimeException("Problem reading file into properties: " + file.getAbsolutePath());
    } finally {
      closeQuietly(fileInputStream);
    }
    return properties;
  }
  
  /**
   * read properties from a resource, dont modify the properties returned since they are cached
   * @param resourceName the resource name (property key)
   * @param useCache  whether or not to use cache
   * @param exceptionIfNotExist throw an exception if the resource does not exist
   * @param classInJar if not null, then look for the jar where this file is, and look in the same dir
   * @param callingLog container for "Reading resource ... from" log messages
   * @return the properties or null if not exist
   */
  public synchronized static Properties propertiesFromResourceName(String resourceName, boolean useCache, 
      boolean exceptionIfNotExist, Class<?> classInJar, StringBuilder callingLog) {

    Properties properties = resourcePropertiesCache.get(resourceName);
    
    if (!useCache || !resourcePropertiesCache.containsKey(resourceName)) {
  
      properties = new Properties();

      boolean success = false;
      
      URL url = computeUrl(resourceName, true);
      InputStream inputStream = null;
      try {
        inputStream = url.openStream();
        properties.load(inputStream);
        success = true;
        String theLog = "Reading resource: " + resourceName + ", from: " + url.toURI();
        if (callingLog != null) {
          callingLog.append(theLog);
        }
      } catch (Exception e) {
        
        //clear out just in case
        properties.clear();

        //lets look next to jar
        File jarFile = classInJar == null ? null : jarFile(classInJar);
        File parentDir = jarFile == null ? null : jarFile.getParentFile();
        String fileName = parentDir == null ? null 
            : (stripLastSlashIfExists(fileCanonicalPath(parentDir)) + File.separator + resourceName);
        File configFile = fileName == null ? null 
            : new File(fileName);

        try {
          //looks like we have a match
          if (configFile != null && configFile.exists() && configFile.isFile()) {
            inputStream = new FileInputStream(configFile);
            properties.load(inputStream);
            success = true;
            String theLog = "Reading resource: " + resourceName + ", from: " + fileCanonicalPath(configFile);
            if (callingLog != null) {
              callingLog.append(theLog);
            }
          }
          
        } catch (Exception e2) {
        }
        if (!success) {
          properties = null;
          if (exceptionIfNotExist) {
            throw new RuntimeException("Problem with resource: '" + resourceName + "'", e);
          }
        }
      } finally {
        closeQuietly(inputStream);
        
        if (useCache && properties != null && properties.size() > 0) {
          resourcePropertiesCache.put(resourceName, properties);
        }
      }
    }
    
    return properties;
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
   * this assumes the property exists, and is a simple property
   * @param object the object
   * @param property the property
   * @return the value
   */
  public static Object propertyValue(Object object, String property)  {
    Method getter = getter(object.getClass(), property, true, true);
    Object result = invokeMethod(getter, object);
    return result;
  }

  /**
   * get a value (trimmed to e) from a property file
   * @param properties the properties
   * @param key the key used to lookup the property value
   * @return the property value
   */
  public static String propertiesValue(Properties properties, String key) {
    return propertiesValue(properties, null, key);
  }
  
  /**
   * get a value (trimmed to e) from a property file
   * @param properties the properties
   * @param overrideMap for testing, to override some properties values
   * @param key the key used to lookup the property value
   * @return the property value
   */
  public static String propertiesValue(Properties properties, Map<String, String> overrideMap, String key) {
    return propertiesValue(properties, overrideMap, null, key);
  }

  /**
   * get a value (trimmed to e) from a property file
   * @param properties the properties
   * @param overrideMap for testing or threadlocal, to override some properties values
   * @param overrideMap2 for testing, to provide some properties values
   * @param key the key used to lookup the property value
   * @return the property value
   */
  public static String propertiesValue(Properties properties, Map<String, String> overrideMap, Map<String, String> overrideMap2, String key) {
    String value = overrideMap == null ? null : overrideMap.get(key);
    if (isBlank(value)) {
      value = overrideMap2 == null ? null : overrideMap2.get(key);
    }
    if (isBlank(value)) {
      value = properties.getProperty(key);
    }
    value = trim(value);
    value = substituteCommonVars(value);
    return value;
  }
  
  /**
   * substitute common vars like $space$ and $newline$
   * @param string The string that potentially contains '$space$' and '$newline$' tokens
   * @return the string with tokens replaced by their represented characters
   */
  public static String substituteCommonVars(String string) {
    if (string == null) {
      return string;
    }
    //short circuit
    if (string.indexOf('$') < 0) {
      return string;
    }
    //might have $space$
    string = replace(string, "$space$", " ");
    
    //note, at some point we could be OS specific
    string = replace(string, "$newline$", "\n"); 
    return string;
  }
  
  /**
   * get a boolean property, or the default if can't find
   * @param properties the properties
   * @param propertyName the property name key
   * @param defaultValue the value to use when key lookup is blank
   * @return the boolean
   */
  public static boolean propertiesValueBoolean(Properties properties,
      String propertyName, boolean defaultValue) {
    return propertiesValueBoolean(properties, null, propertyName, defaultValue);
  }
  
  /**
   * get a boolean property, or the default if cant find.  Validate also with a descriptive exception if problem
   * @param resourceName the resource name
   * @param properties the properties
   * @param overrideMap for testing to override properties
   * @param propertyName the property name key
   * @param defaultValue the value to use when key lookup is blank
   * @param required whether or not a value is required
   * @return the boolean
   */
  public static boolean propertiesValueBoolean(String resourceName, Properties properties, 
      Map<String, String> overrideMap, String propertyName, boolean defaultValue, boolean required) {
    propertyValidateValueBoolean(resourceName, properties, overrideMap, propertyName, required, true);

    Map<String, String> threadLocalMap = propertiesThreadLocalOverrideMap(resourceName);
    
    return propertiesValueBoolean(properties, threadLocalMap, overrideMap, propertyName, defaultValue);
  }
  
  /**
   * get an int property, or the default if can't find.  Validate also with a descriptive exception if problem
   * @param resourceName the resource name
   * @param properties the properties
   * @param overrideMap for testing to override properties
   * @param propertyName the property name key
   * @param defaultValue the value to use when key lookup is blank
   * @param required whether or not a value is required
   * @return the int
   */
  public static int propertiesValueInt(String resourceName, Properties properties, 
      Map<String, String> overrideMap, String propertyName, int defaultValue, boolean required) {
    
    propertyValidateValueInt(resourceName, properties, overrideMap, propertyName, required, true);

    Map<String, String> threadLocalMap = propertiesThreadLocalOverrideMap(resourceName);

    return propertiesValueInt(properties, threadLocalMap, overrideMap, propertyName, defaultValue);
  }

  /**
   * get a property.  Validate also with a descriptive exception if problem
   * @param resourceName the resource name
   * @param properties the properties
   * @param overrideMap for threadlocal or testing to override properties
   * @param propertyName the property name
   * @param required whether or not a value is required
   * @return the string
   */
  public static String propertiesValue(String resourceName, Properties properties, 
      Map<String, String> overrideMap, String propertyName, boolean required) {

    if (required) {
      propertyValidateValueRequired(resourceName, properties, overrideMap, propertyName, true);
    }
    Map<String, String> threadLocalMap = propertiesThreadLocalOverrideMap(resourceName);

    return propertiesValue(properties, threadLocalMap, overrideMap, propertyName);
  }

  /**
   * get a int property, or the default if cant find
   * @param properties the properties
   * @param overrideMap for testing to override properties
   * @param propertyName the name of the property
   * @param defaultValue the value to use when the property value is blank
   * @return the int
   */
  public static int propertiesValueInt(Properties properties, 
      Map<String, String> overrideMap, String propertyName, int defaultValue) {
    return propertiesValueInt(properties, overrideMap, null, propertyName, defaultValue);
  }


  /**
   * get a int property, or the default if can't find
   * @param properties the properties
   * @param overrideMap for testing to override properties
   * @param overrideMap2 for testing to override properties
   * @param propertyName the name of the property
   * @param defaultValue the value to use when the property value is blank
   * @return the int
   */
  public static int propertiesValueInt(Properties properties, 
      Map<String, String> overrideMap, Map<String, String> overrideMap2, String propertyName, int defaultValue) {

    String value = propertiesValue(properties, overrideMap, overrideMap2, propertyName);
    if (isBlank(value)) {
      return defaultValue;
    }

    try {
      return intValue(value);
    } catch (Exception e) {}
    
    throw new RuntimeException("Invalid int value: '" + value + "' for property: " + propertyName + " in grouper.properties");

  }
  
  /**
   * get a boolean property, or the default if can't find
   * @param properties the properties being searched
   * @param overrideMap for testing to override properties
   * @param propertyName the name of the property
   * @param defaultValue the value to use when the property value is blank
   * @return the boolean
   */
  public static boolean propertiesValueBoolean(Properties properties, 
      Map<String, String> overrideMap, String propertyName, boolean defaultValue) {
    return propertiesValueBoolean(properties, overrideMap, null, propertyName, defaultValue);
  }

  /**
   * get a boolean property, or the default if can't find
   * @param properties the properties being searched
   * @param overrideMap for testing or threadlocal to override properties
   * @param overrideMap2 for testing or threadlocal to override properties
   * @param propertyName the name of the property
   * @param defaultValue the value to use when the property value is blank
   * @return the boolean
   */
  public static boolean propertiesValueBoolean(Properties properties, 
      Map<String, String> overrideMap, Map<String, String> overrideMap2, String propertyName, boolean defaultValue) {
    
      
    String value = propertiesValue(properties, overrideMap, overrideMap2, propertyName);
    if (isBlank(value)) {
      return defaultValue;
    }
    
    if ("true".equalsIgnoreCase(value)) {
      return true;
    }
    if ("false".equalsIgnoreCase(value)) {
      return false;
    }
    if ("t".equalsIgnoreCase(value)) {
      return true;
    }
    if ("f".equalsIgnoreCase(value)) {
      return false;
    }
    throw new RuntimeException("Invalid boolean value: '" + value + "' for property: " + propertyName + " in properties file");

  }
  
  /**
   * close a connection null safe and don't throw exception
   * @param connection the connection to close
   */
  public static void closeQuietly(Connection connection) {
    if (connection != null) {
      try {
        connection.close();
      } catch (Exception e) {
        //ignore
      }
    }
  }

  /**
   * close a statement null safe and don't throw exception
   * @param statement the statement to close
   */
  public static void closeQuietly(Statement statement) {
    if (statement != null) {
      try {
        statement.close();
      } catch (Exception e) {
        //ignore
      }
    }
  }

  /**
   * close a resultSet null safe and don't throw exception
   * @param resultSet the ResultSet to close
   */
  public static void closeQuietly(ResultSet resultSet) {
    if (resultSet != null) {
      try {
        resultSet.close();
      } catch (Exception e) {
        //ignore
      }
    }
  }

  /** cache the hostname, it won't change */
  private static String hostname = null;

  /**
   * get the hostname of this machine
   * @return the hostname
   */
  public static String hostname() {
  
    if (isBlank(hostname)) {
  
      //get the hostname
      hostname = "unknown";
      try {
        InetAddress addr = InetAddress.getLocalHost();
  
        // Get hostname
        hostname = addr.getHostName();
      } catch (Exception e) {
        System.err.println("Cant find servers hostname: ");
        e.printStackTrace();
      }
    }
  
    return hostname;
  }

  /**
   * is ascii char
   * @param input the charater to test
   * @return true if ascii (has value below 128)
   */
  public static boolean isAscii(char input) {
    return input < 128;
  }

  /**
   * find the length of ascii chars (non ascii are counted as two)
   * @param input the input string
   * @return the length of ascii chars
   */
  public static int lengthAscii(String input) {
    if (input == null) {
      return 0;
    }
    //see what real length is
    int utfLength = input.length();
    //count how many non asciis
    int extras = 0;
    for (int i=0;i<utfLength;i++) {
      //keep count of non ascii chars
      if (!isAscii(input.charAt(i))) {
        extras++;
      }
    }
    return utfLength + extras;
  }

  /**
   * rollback a connection quietly
   * @param connection the connection to roll back
   */
  public static void rollbackQuietly(Connection connection) {
    if (connection != null) {
      try {
        connection.rollback();
      } catch (Exception e) {
        //ignore
      }
    }
  }

  /**
   * find the length of ascii chars (non ascii are counted as two)
   * @param input is the string to operate on
   * @param requiredLength length we need the string to be
   * @return the length of ascii chars
   */
  public static String truncateAscii(String input, int requiredLength) {
    if (input == null) {
      return input;
    }
    //see what real length is
    int utfLength = input.length();
    
    //see if not worth checking
    if (utfLength * 2 < requiredLength) {
      return input;
    }
    
    //count how many non asciis
    int asciiLength = 0;
    for (int i=0;i<utfLength;i++) {
      
      asciiLength++;
      
      //keep count of non ascii chars
      if (!isAscii(input.charAt(i))) {
        asciiLength++;
      }
      
      //see if we are over 
      if (asciiLength > requiredLength) {
        //do not include the current char
        return input.substring(0,i);
      }
    }
    //must have fit
    return input;
  }
  
  /**
   * if the input is a file, read string from file.  if not, or if disabled from grouper.properties, return the input
   * @param in A path to a file
   * @param disableExternalFileLookup when true, no attempt is made to read the input file reference into a String
   * @return the contents of the file referred to by the input, or the original input string
   */
  public static String readFromFileIfFile(String in, boolean disableExternalFileLookup) {
    
    String theIn = in;
    //convert both slashes to file slashes
    if (File.separatorChar == '/') {
      theIn = replace(theIn, "\\", "/");
    } else {
      theIn = replace(theIn, "/", "\\");
    }
    
    //see if it is a file reference
    if (theIn.indexOf(File.separatorChar) != -1 && !disableExternalFileLookup) {
      //read the contents of the file into a string
      theIn = readFileIntoString(new File(theIn));
      return theIn;
    }
    return in;
  
  }

  /**
   * Create directories, throw exception if not possible.
   * This is will be ok if the directory already exists (will not delete it)
   * @param dir the directory to create
   */
  public static void mkdirs(File dir) {
    if (!dir.exists()) {
      if (!dir.mkdirs()) {
        throw new RuntimeException("Could not create directory : " + dir.getParentFile());
      }
      return;
    }
    if (!dir.isDirectory()) {
      throw new RuntimeException("Should be a directory but is not: " + dir);
    }
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
   * 
   * @param str string to check
   * @return true if not blank
   */
  public static boolean isNotBlank(String str) {
    return !isBlank(str);
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

  /**
   * trim to empty, convert null to empty
   * @param str a string containing whitespace, or null
   * @return A trimmed string, potentially of length 0 in the case of all-whitespace or null input
   */
  public static String trimToEmpty(String str) {
    return str == null ? "" : str.trim();
  }

  /**
   * <p>Abbreviates a String using ellipses. This will turn
   * "Now is the time for all good men" into "Now is the time for..."</p>
   *
   * <p>Specifically:</p>
   * <ul>
   *   <li>If <code>str</code> is less than <code>maxWidth</code> characters
   *       long, return it.</li>
   *   <li>Else abbreviate it to <code>(substring(str, 0, max-3) + "...")</code>.</li>
   *   <li>If <code>maxWidth</code> is less than <code>4</code>, throw an
   *       <code>IllegalArgumentException</code>.</li>
   *   <li>In no case will it return a String of length greater than
   *       <code>maxWidth</code>.</li>
   * </ul>
   *
   * <pre>
   * StringUtils.abbreviate(null, *)      = null
   * StringUtils.abbreviate("", 4)        = ""
   * StringUtils.abbreviate("abcdefg", 6) = "abc..."
   * StringUtils.abbreviate("abcdefg", 7) = "abcdefg"
   * StringUtils.abbreviate("abcdefg", 8) = "abcdefg"
   * StringUtils.abbreviate("abcdefg", 4) = "a..."
   * StringUtils.abbreviate("abcdefg", 3) = IllegalArgumentException
   * </pre>
   *
   * @param str  the String to check, may be null
   * @param maxWidth  maximum length of result String, must be at least 4
   * @return abbreviated String, <code>null</code> if null String input
   * @throws IllegalArgumentException if the width is too small
   * @since 2.0
   */
  public static String abbreviate(String str, int maxWidth) {
    return abbreviate(str, 0, maxWidth);
  }

  /**
   * <p>Abbreviates a String using ellipses. This will turn
   * "Now is the time for all good men" into "...is the time for..."</p>
   *
   * <p>Works like <code>abbreviate(String, int)</code>, but allows you to specify
   * a "left edge" offset.  Note that this left edge is not necessarily going to
   * be the leftmost character in the result, or the first character following the
   * ellipses, but it will appear somewhere in the result.
   *
   * <p>In no case will it return a String of length greater than
   * <code>maxWidth</code>.</p>
   *
   * <pre>
   * StringUtils.abbreviate(null, *, *)                = null
   * StringUtils.abbreviate("", 0, 4)                  = ""
   * StringUtils.abbreviate("abcdefghijklmno", -1, 10) = "abcdefg..."
   * StringUtils.abbreviate("abcdefghijklmno", 0, 10)  = "abcdefg..."
   * StringUtils.abbreviate("abcdefghijklmno", 1, 10)  = "abcdefg..."
   * StringUtils.abbreviate("abcdefghijklmno", 4, 10)  = "abcdefg..."
   * StringUtils.abbreviate("abcdefghijklmno", 5, 10)  = "...fghi..."
   * StringUtils.abbreviate("abcdefghijklmno", 6, 10)  = "...ghij..."
   * StringUtils.abbreviate("abcdefghijklmno", 8, 10)  = "...ijklmno"
   * StringUtils.abbreviate("abcdefghijklmno", 10, 10) = "...ijklmno"
   * StringUtils.abbreviate("abcdefghijklmno", 12, 10) = "...ijklmno"
   * StringUtils.abbreviate("abcdefghij", 0, 3)        = IllegalArgumentException
   * StringUtils.abbreviate("abcdefghij", 5, 6)        = IllegalArgumentException
   * </pre>
   *
   * @param str  the String to check, may be null
   * @param offset  left edge of source String
   * @param maxWidth  maximum length of result String, must be at least 4
   * @return abbreviated String, <code>null</code> if null String input
   * @throws IllegalArgumentException if the width is too small
   * @since 2.0
   */
  public static String abbreviate(String str, int offset, int maxWidth) {
    if (str == null) {
      return null;
    }
    if (maxWidth < 4) {
      throw new IllegalArgumentException("Minimum abbreviation width is 4");
    }
    if (str.length() <= maxWidth) {
      return str;
    }
    if (offset > str.length()) {
      offset = str.length();
    }
    if ((str.length() - offset) < (maxWidth - 3)) {
      offset = str.length() - (maxWidth - 3);
    }
    if (offset <= 4) {
      return str.substring(0, maxWidth - 3) + "...";
    }
    if (maxWidth < 7) {
      throw new IllegalArgumentException("Minimum abbreviation width with offset is 7");
    }
    if ((offset + (maxWidth - 3)) < str.length()) {
      return "..." + abbreviate(str.substring(offset), maxWidth - 3);
    }
    return "..." + str.substring(str.length() - (maxWidth - 3));
  }

  // Splitting
  //-----------------------------------------------------------------------
  /**
   * <p>Splits the provided text into an array, using whitespace as the
   * separator.
   * Whitespace is defined by {@link Character#isWhitespace(char)}.</p>
   *
   * <p>The separator is not included in the returned String array.
   * Adjacent separators are treated as one separator.
   * For more control over the split use the StrTokenizer class.</p>
   *
   * <p>A <code>null</code> input String returns <code>null</code>.</p>
   *
   * <pre>
   * StringUtils.split(null)       = null
   * StringUtils.split("")         = []
   * StringUtils.split("abc def")  = ["abc", "def"]
   * StringUtils.split("abc  def") = ["abc", "def"]
   * StringUtils.split(" abc ")    = ["abc"]
   * </pre>
   *
   * @param str  the String to parse, may be null
   * @return an array of parsed Strings, <code>null</code> if null String input
   */
  public static String[] split(String str) {
    return split(str, null, -1);
  }

  /**
   * <p>Splits the provided text into an array, separator specified.
   * This is an alternative to using StringTokenizer.</p>
   *
   * <p>The separator is not included in the returned String array.
   * Adjacent separators are treated as one separator.
   * For more control over the split use the StrTokenizer class.</p>
   *
   * <p>A <code>null</code> input String returns <code>null</code>.</p>
   *
   * <pre>
   * StringUtils.split(null, *)         = null
   * StringUtils.split("", *)           = []
   * StringUtils.split("a.b.c", '.')    = ["a", "b", "c"]
   * StringUtils.split("a..b.c", '.')   = ["a", "b", "c"]
   * StringUtils.split("a:b:c", '.')    = ["a:b:c"]
   * StringUtils.split("a\tb\nc", null) = ["a", "b", "c"]
   * StringUtils.split("a b c", ' ')    = ["a", "b", "c"]
   * </pre>
   *
   * @param str  the String to parse, may be null
   * @param separatorChar  the character used as the delimiter,
   *  <code>null</code> splits on whitespace
   * @return an array of parsed Strings, <code>null</code> if null String input
   * @since 2.0
   */
  public static String[] split(String str, char separatorChar) {
    return splitWorker(str, separatorChar, false);
  }

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

  /**
   * <p>Splits the provided text into an array with a maximum length,
   * separators specified.</p>
   *
   * <p>The separator is not included in the returned String array.
   * Adjacent separators are treated as one separator.</p>
   *
   * <p>A <code>null</code> input String returns <code>null</code>.
   * A <code>null</code> separatorChars splits on whitespace.</p>
   *
   * <p>If more than <code>max</code> delimited substrings are found, the last
   * returned string includes all characters after the first <code>max - 1</code>
   * returned strings (including separator characters).</p>
   *
   * <pre>
   * StringUtils.split(null, *, *)            = null
   * StringUtils.split("", *, *)              = []
   * StringUtils.split("ab de fg", null, 0)   = ["ab", "cd", "ef"]
   * StringUtils.split("ab   de fg", null, 0) = ["ab", "cd", "ef"]
   * StringUtils.split("ab:cd:ef", ":", 0)    = ["ab", "cd", "ef"]
   * StringUtils.split("ab:cd:ef", ":", 2)    = ["ab", "cd:ef"]
   * </pre>
   *
   * @param str  the String to parse, may be null
   * @param separatorChars  the characters used as the delimiters,
   *  <code>null</code> splits on whitespace
   * @param max  the maximum number of elements to include in the
   *  array. A zero or negative value implies no limit
   * @return an array of parsed Strings, <code>null</code> if null String input
   */
  public static String[] split(String str, String separatorChars, int max) {
    return splitWorker(str, separatorChars, max, false);
  }

  /**
   * <p>Splits the provided text into an array, separator string specified.</p>
   *
   * <p>The separator(s) will not be included in the returned String array.
   * Adjacent separators are treated as one separator.</p>
   *
   * <p>A <code>null</code> input String returns <code>null</code>.
   * A <code>null</code> separator splits on whitespace.</p>
   *
   * <pre>
   * StringUtils.split(null, *)            = null
   * StringUtils.split("", *)              = []
   * StringUtils.split("ab de fg", null)   = ["ab", "de", "fg"]
   * StringUtils.split("ab   de fg", null) = ["ab", "de", "fg"]
   * StringUtils.split("ab:cd:ef", ":")    = ["ab", "cd", "ef"]
   * StringUtils.split("abstemiouslyaeiouyabstemiously", "aeiouy")  = ["bst", "m", "sl", "bst", "m", "sl"]
   * StringUtils.split("abstemiouslyaeiouyabstemiously", "aeiouy")  = ["abstemiously", "abstemiously"]
   * </pre>
   *
   * @param str  the String to parse, may be null
   * @param separator  String containing the String to be used as a delimiter,
   *  <code>null</code> splits on whitespace
   * @return an array of parsed Strings, <code>null</code> if null String was input
   */
  public static String[] splitByWholeSeparator(String str, String separator) {
    return splitByWholeSeparator(str, separator, -1);
  }

  /**
   * <p>Splits the provided text into an array, separator string specified.
   * Returns a maximum of <code>max</code> substrings.</p>
   *
   * <p>The separator(s) will not be included in the returned String array.
   * Adjacent separators are treated as one separator.</p>
   *
   * <p>A <code>null</code> input String returns <code>null</code>.
   * A <code>null</code> separator splits on whitespace.</p>
   *
   * <pre>
   * StringUtils.splitByWholeSeparator(null, *, *)               = null
   * StringUtils.splitByWholeSeparator("", *, *)                 = []
   * StringUtils.splitByWholeSeparator("ab de fg", null, 0)      = ["ab", "de", "fg"]
   * StringUtils.splitByWholeSeparator("ab   de fg", null, 0)    = ["ab", "de", "fg"]
   * StringUtils.splitByWholeSeparator("ab:cd:ef", ":", 2)       = ["ab", "cd"]
   * StringUtils.splitByWholeSeparator("abstemiouslyaeiouyabstemiously", "aeiouy", 2) = ["bst", "m"]
   * StringUtils.splitByWholeSeparator("abstemiouslyaeiouyabstemiously", "aeiouy", 2)  = ["abstemiously", "abstemiously"]
   * </pre>
   *
   * @param str  the String to parse, may be null
   * @param separator  String containing the String to be used as a delimiter,
   *  <code>null</code> splits on whitespace
   * @param max  the maximum number of elements to include in the returned
   *  array. A zero or negative value implies no limit.
   * @return an array of parsed Strings, <code>null</code> if null String was input
   */
  @SuppressWarnings("unchecked")
  public static String[] splitByWholeSeparator(String str, String separator, int max) {
    if (str == null) {
      return null;
    }

    int len = str.length();

    if (len == 0) {
      return EMPTY_STRING_ARRAY;
    }

    if ((separator == null) || ("".equals(separator))) {
      // Split on whitespace.
      return split(str, null, max);
    }

    int separatorLength = separator.length();

    ArrayList substrings = new ArrayList();
    int numberOfSubstrings = 0;
    int beg = 0;
    int end = 0;
    while (end < len) {
      end = str.indexOf(separator, beg);

      if (end > -1) {
        if (end > beg) {
          numberOfSubstrings += 1;

          if (numberOfSubstrings == max) {
            end = len;
            substrings.add(str.substring(beg));
          } else {
            // The following is OK, because String.substring( beg, end ) excludes
            // the character at the position 'end'.
            substrings.add(str.substring(beg, end));

            // Set the starting point for the next search.
            // The following is equivalent to beg = end + (separatorLength - 1) + 1,
            // which is the right calculation:
            beg = end + separatorLength;
          }
        } else {
          // We found a consecutive occurrence of the separator, so skip it.
          beg = end + separatorLength;
        }
      } else {
        // String.substring( beg ) goes from 'beg' to the end of the String.
        substrings.add(str.substring(beg));
        end = len;
      }
    }

    return (String[]) substrings.toArray(new String[substrings.size()]);
  }

  //-----------------------------------------------------------------------
  /**
   * <p>Splits the provided text into an array, using whitespace as the
   * separator, preserving all tokens, including empty tokens created by 
   * adjacent separators. This is an alternative to using StringTokenizer.
   * Whitespace is defined by {@link Character#isWhitespace(char)}.</p>
   *
   * <p>The separator is not included in the returned String array.
   * Adjacent separators are treated as separators for empty tokens.
   * For more control over the split use the StrTokenizer class.</p>
   *
   * <p>A <code>null</code> input String returns <code>null</code>.</p>
   *
   * <pre>
   * StringUtils.splitPreserveAllTokens(null)       = null
   * StringUtils.splitPreserveAllTokens("")         = []
   * StringUtils.splitPreserveAllTokens("abc def")  = ["abc", "def"]
   * StringUtils.splitPreserveAllTokens("abc  def") = ["abc", "", "def"]
   * StringUtils.splitPreserveAllTokens(" abc ")    = ["", "abc", ""]
   * </pre>
   *
   * @param str  the String to parse, may be <code>null</code>
   * @return an array of parsed Strings, <code>null</code> if null String input
   * @since 2.1
   */
  public static String[] splitPreserveAllTokens(String str) {
    return splitWorker(str, null, -1, true);
  }

  /**
   * <p>Splits the provided text into an array, separator specified,
   * preserving all tokens, including empty tokens created by adjacent
   * separators. This is an alternative to using StringTokenizer.</p>
   *
   * <p>The separator is not included in the returned String array.
   * Adjacent separators are treated as separators for empty tokens.
   * For more control over the split use the StrTokenizer class.</p>
   *
   * <p>A <code>null</code> input String returns <code>null</code>.</p>
   *
   * <pre>
   * StringUtils.splitPreserveAllTokens(null, *)         = null
   * StringUtils.splitPreserveAllTokens("", *)           = []
   * StringUtils.splitPreserveAllTokens("a.b.c", '.')    = ["a", "b", "c"]
   * StringUtils.splitPreserveAllTokens("a..b.c", '.')   = ["a", "b", "c"]
   * StringUtils.splitPreserveAllTokens("a:b:c", '.')    = ["a:b:c"]
   * StringUtils.splitPreserveAllTokens("a\tb\nc", null) = ["a", "b", "c"]
   * StringUtils.splitPreserveAllTokens("a b c", ' ')    = ["a", "b", "c"]
   * StringUtils.splitPreserveAllTokens("a b c ", ' ')   = ["a", "b", "c", ""]
   * StringUtils.splitPreserveAllTokens("a b c ", ' ')   = ["a", "b", "c", "", ""]
   * StringUtils.splitPreserveAllTokens(" a b c", ' ')   = ["", a", "b", "c"]
   * StringUtils.splitPreserveAllTokens("  a b c", ' ')  = ["", "", a", "b", "c"]
   * StringUtils.splitPreserveAllTokens(" a b c ", ' ')  = ["", a", "b", "c", ""]
   * </pre>
   *
   * @param str  the String to parse, may be <code>null</code>
   * @param separatorChar  the character used as the delimiter,
   *  <code>null</code> splits on whitespace
   * @return an array of parsed Strings, <code>null</code> if null String input
   * @since 2.1
   */
  public static String[] splitPreserveAllTokens(String str, char separatorChar) {
    return splitWorker(str, separatorChar, true);
  }

  /**
   * Performs the logic for the <code>split</code> and 
   * <code>splitPreserveAllTokens</code> methods that do not return a
   * maximum array length.
   *
   * @param str  the String to parse, may be <code>null</code>
   * @param separatorChar the separate character
   * @param preserveAllTokens if <code>true</code>, adjacent separators are
   * treated as empty token separators; if <code>false</code>, adjacent
   * separators are treated as one separator.
   * @return an array of parsed Strings, <code>null</code> if null String input
   */
  @SuppressWarnings("unchecked")
  private static String[] splitWorker(String str, char separatorChar,
      boolean preserveAllTokens) {
    // Performance tuned for 2.0 (JDK1.4)

    if (str == null) {
      return null;
    }
    int len = str.length();
    if (len == 0) {
      return EMPTY_STRING_ARRAY;
    }
    List list = new ArrayList();
    int i = 0, start = 0;
    boolean match = false;
    boolean lastMatch = false;
    while (i < len) {
      if (str.charAt(i) == separatorChar) {
        if (match || preserveAllTokens) {
          list.add(str.substring(start, i));
          match = false;
          lastMatch = true;
        }
        start = ++i;
        continue;
      }
      lastMatch = false;
      match = true;
      i++;
    }
    if (match || (preserveAllTokens && lastMatch)) {
      list.add(str.substring(start, i));
    }
    return (String[]) list.toArray(new String[list.size()]);
  }

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
   * <p>Splits the provided text into an array with a maximum length,
   * separators specified, preserving all tokens, including empty tokens 
   * created by adjacent separators.</p>
   *
   * <p>The separator is not included in the returned String array.
   * Adjacent separators are treated as separators for empty tokens.
   * Adjacent separators are treated as one separator.</p>
   *
   * <p>A <code>null</code> input String returns <code>null</code>.
   * A <code>null</code> separatorChars splits on whitespace.</p>
   *
   * <p>If more than <code>max</code> delimited substrings are found, the last
   * returned string includes all characters after the first <code>max - 1</code>
   * returned strings (including separator characters).</p>
   *
   * <pre>
   * StringUtils.splitPreserveAllTokens(null, *, *)            = null
   * StringUtils.splitPreserveAllTokens("", *, *)              = []
   * StringUtils.splitPreserveAllTokens("ab de fg", null, 0)   = ["ab", "cd", "ef"]
   * StringUtils.splitPreserveAllTokens("ab   de fg", null, 0) = ["ab", "cd", "ef"]
   * StringUtils.splitPreserveAllTokens("ab:cd:ef", ":", 0)    = ["ab", "cd", "ef"]
   * StringUtils.splitPreserveAllTokens("ab:cd:ef", ":", 2)    = ["ab", "cd:ef"]
   * StringUtils.splitPreserveAllTokens("ab   de fg", null, 2) = ["ab", "  de fg"]
   * StringUtils.splitPreserveAllTokens("ab   de fg", null, 3) = ["ab", "", " de fg"]
   * StringUtils.splitPreserveAllTokens("ab   de fg", null, 4) = ["ab", "", "", "de fg"]
   * </pre>
   *
   * @param str  the String to parse, may be <code>null</code>
   * @param separatorChars  the characters used as the delimiters,
   *  <code>null</code> splits on whitespace
   * @param max  the maximum number of elements to include in the
   *  array. A zero or negative value implies no limit
   * @return an array of parsed Strings, <code>null</code> if null String input
   * @since 2.1
   */
  public static String[] splitPreserveAllTokens(String str, String separatorChars, int max) {
    return splitWorker(str, separatorChars, max, true);
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
   * <p>Joins the elements of the provided array into a single String
   * containing the provided list of elements.</p>
   *
   * <p>No separator is added to the joined String.
   * Null objects or empty strings within the array are represented by
   * empty strings.</p>
   *
   * <pre>
   * StringUtils.join(null)            = null
   * StringUtils.join([])              = ""
   * StringUtils.join([null])          = ""
   * StringUtils.join(["a", "b", "c"]) = "abc"
   * StringUtils.join([null, "", "a"]) = "a"
   * </pre>
   *
   * @param array  the array of values to join together, may be null
   * @return the joined String, <code>null</code> if null array input
   * @since 2.0
   */
  public static String join(Object[] array) {
    return join(array, null);
  }

  /**
   * <p>Joins the elements of the provided array into a single String
   * containing the provided list of elements.</p>
   *
   * <p>No delimiter is added before or after the list.
   * Null objects or empty strings within the array are represented by
   * empty strings.</p>
   *
   * <pre>
   * StringUtils.join(null, *)               = null
   * StringUtils.join([], *)                 = ""
   * StringUtils.join([null], *)             = ""
   * StringUtils.join(["a", "b", "c"], ';')  = "a;b;c"
   * StringUtils.join(["a", "b", "c"], null) = "abc"
   * StringUtils.join([null, "", "a"], ';')  = ";;a"
   * </pre>
   *
   * @param array  the array of values to join together, may be null
   * @param separator  the separator character to use
   * @return the joined String, <code>null</code> if null array input
   * @since 2.0
   */
  public static String join(Object[] array, char separator) {
    if (array == null) {
      return null;
    }
    int arraySize = array.length;
    int bufSize = (arraySize == 0 ? 0 : ((array[0] == null ? 16 : array[0].toString()
        .length()) + 1)
        * arraySize);
    StringBuffer buf = new StringBuffer(bufSize);

    for (int i = 0; i < arraySize; i++) {
      if (i > 0) {
        buf.append(separator);
      }
      if (array[i] != null) {
        buf.append(array[i]);
      }
    }
    return buf.toString();
  }

  /**
   * <p>Joins the elements of the provided array into a single String
   * containing the provided list of elements.</p>
   *
   * <p>No delimiter is added before or after the list.
   * A <code>null</code> separator is the same as an empty String ("").
   * Null objects or empty strings within the array are represented by
   * empty strings.</p>
   *
   * <pre>
   * StringUtils.join(null, *)                = null
   * StringUtils.join([], *)                  = ""
   * StringUtils.join([null], *)              = ""
   * StringUtils.join(["a", "b", "c"], "--")  = "a--b--c"
   * StringUtils.join(["a", "b", "c"], null)  = "abc"
   * StringUtils.join(["a", "b", "c"], "")    = "abc"
   * StringUtils.join([null, "", "a"], ',')   = ",,a"
   * </pre>
   *
   * @param array  the array of values to join together, may be null
   * @param separator  the separator character to use, null treated as ""
   * @return the joined String, <code>null</code> if null array input
   */
  public static String join(Object[] array, String separator) {
    if (array == null) {
      return null;
    }
    if (separator == null) {
      separator = "";
    }
    int arraySize = array.length;

    // ArraySize ==  0: Len = 0
    // ArraySize > 0:   Len = NofStrings *(len(firstString) + len(separator))
    //           (Assuming that all Strings are roughly equally long)
    int bufSize = ((arraySize == 0) ? 0 : arraySize
        * ((array[0] == null ? 16 : array[0].toString().length()) + separator.length()));

    StringBuffer buf = new StringBuffer(bufSize);

    for (int i = 0; i < arraySize; i++) {
      if (i > 0) {
        buf.append(separator);
      }
      if (array[i] != null) {
        buf.append(array[i]);
      }
    }
    return buf.toString();
  }

  /**
   * <p>Joins the elements of the provided <code>Iterator</code> into
   * a single String containing the provided elements.</p>
   *
   * <p>No delimiter is added before or after the list. Null objects or empty
   * strings within the iteration are represented by empty strings.</p>
   *
   * <p>See the examples here: {@link #join(Object[],char)}. </p>
   *
   * @param iterator  the <code>Iterator</code> of values to join together, may be null
   * @param separator  the separator character to use
   * @return the joined String, <code>null</code> if null iterator input
   * @since 2.0
   */
  public static String join(Iterator iterator, char separator) {
    if (iterator == null) {
      return null;
    }
    StringBuffer buf = new StringBuffer(256); // Java default is 16, probably too small
    while (iterator.hasNext()) {
      Object obj = iterator.next();
      if (obj != null) {
        buf.append(obj);
      }
      if (iterator.hasNext()) {
        buf.append(separator);
      }
    }
    return buf.toString();
  }

  /**
   * <p>Joins the elements of the provided <code>Iterator</code> into
   * a single String containing the provided elements.</p>
   *
   * <p>No delimiter is added before or after the list.
   * A <code>null</code> separator is the same as an empty String ("").</p>
   *
   * <p>See the examples here: {@link #join(Object[],String)}. </p>
   *
   * @param iterator  the <code>Iterator</code> of values to join together, may be null
   * @param separator  the separator character to use, null treated as ""
   * @return the joined String, <code>null</code> if null iterator input
   */
  public static String join(Iterator iterator, String separator) {
    if (iterator == null) {
      return null;
    }
    StringBuffer buf = new StringBuffer(256); // Java default is 16, probably too small
    while (iterator.hasNext()) {
      Object obj = iterator.next();
      if (obj != null) {
        buf.append(obj);
      }
      if ((separator != null) && iterator.hasNext()) {
        buf.append(separator);
      }
    }
    return buf.toString();
  }

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
   * <p>Returns either the passed in String, or if the String is
   * <code>null</code>, the value of <code>defaultStr</code>.</p>
   *
   * <pre>
   * StringUtils.defaultString(null, "NULL")  = "NULL"
   * StringUtils.defaultString("", "NULL")    = ""
   * StringUtils.defaultString("bat", "NULL") = "bat"
   * </pre>
   *
   * @see String#valueOf(Object)
   * @param str  the String to check, may be null
   * @param defaultStr  the default String to return
   *  if the input is <code>null</code>, may be null
   * @return the passed in String, or the default if it was <code>null</code>
   */
  public static String defaultString(String str, String defaultStr) {
    return str == null ? defaultStr : str;
  }

  /**
   * <p>Returns either the passed in String, or if the String is
   * empty or <code>null</code>, the value of <code>defaultStr</code>.</p>
   *
   * <pre>
   * StringUtils.defaultIfEmpty(null, "NULL")  = "NULL"
   * StringUtils.defaultIfEmpty("", "NULL")    = "NULL"
   * StringUtils.defaultIfEmpty("bat", "NULL") = "bat"
   * </pre>
   *
   * @param str  the String to check, may be null
   * @param defaultStr  the default String to return
   *  if the input is empty ("") or <code>null</code>, may be null
   * @return the passed in String, or the default
   */
  public static String defaultIfEmpty(String str, String defaultStr) {
    return isEmpty(str) ? defaultStr : str;
  }

  /**
   * <p>Capitalizes a String changing the first letter to title case as
   * per {@link Character#toTitleCase(char)}. No other letters are changed.</p>
   *
   * <p>A <code>null</code> input String returns <code>null</code>.</p>
   *
   * <pre>
   * StringUtils.capitalize(null)  = null
   * StringUtils.capitalize("")    = ""
   * StringUtils.capitalize("cat") = "Cat"
   * StringUtils.capitalize("cAt") = "CAt"
   * </pre>
   *
   * @param str  the String to capitalize, may be null
   * @return the capitalized String, <code>null</code> if null String input
   * @since 2.0
   */
  public static String capitalize(String str) {
    int strLen;
    if (str == null || (strLen = str.length()) == 0) {
      return str;
    }
    return new StringBuffer(strLen).append(Character.toTitleCase(str.charAt(0))).append(
        str.substring(1)).toString();
  }

  /**
   * <p>Checks if String contains a search character, handling <code>null</code>.
   * This method uses {@link String#indexOf(int)}.</p>
   *
   * <p>A <code>null</code> or empty ("") String will return <code>false</code>.</p>
   *
   * <pre>
   * StringUtils.contains(null, *)    = false
   * StringUtils.contains("", *)      = false
   * StringUtils.contains("abc", 'a') = true
   * StringUtils.contains("abc", 'z') = false
   * </pre>
   *
   * @param str  the String to check, may be null
   * @param searchChar  the character to find
   * @return true if the String contains the search character,
   *  false if not or <code>null</code> string input
   * @since 2.0
   */
  public static boolean contains(String str, char searchChar) {
    if (isEmpty(str)) {
      return false;
    }
    return str.indexOf(searchChar) >= 0;
  }

  /**
   * <p>Checks if String contains a search String, handling <code>null</code>.
   * This method uses {@link String#indexOf(int)}.</p>
   *
   * <p>A <code>null</code> String will return <code>false</code>.</p>
   *
   * <pre>
   * StringUtils.contains(null, *)     = false
   * StringUtils.contains(*, null)     = false
   * StringUtils.contains("", "")      = true
   * StringUtils.contains("abc", "")   = true
   * StringUtils.contains("abc", "a")  = true
   * StringUtils.contains("abc", "z")  = false
   * </pre>
   *
   * @param str  the String to check, may be null
   * @param searchStr  the String to find, may be null
   * @return true if the String contains the search String,
   *  false if not or <code>null</code> string input
   * @since 2.0
   */
  public static boolean contains(String str, String searchStr) {
    if (str == null || searchStr == null) {
      return false;
    }
    return str.indexOf(searchStr) >= 0;
  }
  
  /**
   * An empty immutable <code>String</code> array.
   */
  public static final String[] EMPTY_STRING_ARRAY = new String[0];

  /**
   * <p>Compares two objects for equality, where either one or both
   * objects may be <code>null</code>.</p>
   *
   * <pre>
   * ObjectUtils.equals(null, null)                  = true
   * ObjectUtils.equals(null, "")                    = false
   * ObjectUtils.equals("", null)                    = false
   * ObjectUtils.equals("", "")                      = true
   * ObjectUtils.equals(Boolean.TRUE, null)          = false
   * ObjectUtils.equals(Boolean.TRUE, "true")        = false
   * ObjectUtils.equals(Boolean.TRUE, Boolean.TRUE)  = true
   * ObjectUtils.equals(Boolean.TRUE, Boolean.FALSE) = false
   * </pre>
   *
   * @param object1  the first object, may be <code>null</code>
   * @param object2  the second object, may be <code>null</code>
   * @return <code>true</code> if the values of both objects are the same
   */
  public static boolean equals(Object object1, Object object2) {
      if (object1 == object2) {
          return true;
      }
      if ((object1 == null) || (object2 == null)) {
          return false;
      }
      return object1.equals(object2);
  }

  /**
   * <p>A way to get the entire nested stack-trace of an throwable.</p>
   *
   * @param throwable  the <code>Throwable</code> to be examined
   * @return the nested stack trace, with the root cause first
   * @since 2.0
   */
  public static String getFullStackTrace(Throwable throwable) {
      StringWriter sw = new StringWriter();
      PrintWriter pw = new PrintWriter(sw, true);
      Throwable[] ts = getThrowables(throwable);
      for (int i = 0; i < ts.length; i++) {
          ts[i].printStackTrace(pw);
          if (isNestedThrowable(ts[i])) {
              break;
          }
      }
      return sw.getBuffer().toString();
  }
  /**
   * <p>Returns the list of <code>Throwable</code> objects in the
   * exception chain.</p>
   * 
   * <p>A throwable without cause will return an array containing
   * one element - the input throwable.
   * A throwable with one cause will return an array containing
   * two elements. - the input throwable and the cause throwable.
   * A <code>null</code> throwable will return an array size zero.</p>
   *
   * @param throwable  the throwable to inspect, may be null
   * @return the array of throwables, never null
   */
  @SuppressWarnings("unchecked")
  public static Throwable[] getThrowables(Throwable throwable) {
      List list = new ArrayList();
      while (throwable != null) {
          list.add(throwable);
          throwable = getCause(throwable);
      }
      return (Throwable[]) list.toArray(new Throwable[list.size()]);
  }
  
  /**
   * <p>The names of methods commonly used to access a wrapped exception.</p>
   */
  private static String[] CAUSE_METHOD_NAMES = {
      "getCause",
      "getNextException",
      "getTargetException",
      "getException",
      "getSourceException",
      "getRootCause",
      "getCausedByException",
      "getNested",
      "getLinkedException",
      "getNestedException",
      "getLinkedCause",
      "getThrowable",
  };

  /**
   * <p>Checks whether this <code>Throwable</code> class can store a cause.</p>
   * 
   * <p>This method does <b>not</b> check whether it actually does store a cause.<p>
   *
   * @param throwable  the <code>Throwable</code> to examine, may be null
   * @return boolean <code>true</code> if nested otherwise <code>false</code>
   * @since 2.0
   */
  public static boolean isNestedThrowable(Throwable throwable) {
      if (throwable == null) {
          return false;
      }

      if (throwable instanceof SQLException) {
          return true;
      } else if (throwable instanceof InvocationTargetException) {
          return true;
      } else if (isThrowableNested()) {
          return true;
      }

      Class cls = throwable.getClass();
      for (int i = 0, isize = CAUSE_METHOD_NAMES.length; i < isize; i++) {
          try {
              Method method = cls.getMethod(CAUSE_METHOD_NAMES[i], (Class[])null);
              if (method != null && Throwable.class.isAssignableFrom(method.getReturnType())) {
                  return true;
              }
          } catch (NoSuchMethodException ignored) {
          } catch (SecurityException ignored) {
          }
      }

      try {
          Field field = cls.getField("detail");
          if (field != null) {
              return true;
          }
      } catch (NoSuchFieldException ignored) {
      } catch (SecurityException ignored) {
      }

      return false;
  }

  /**
   * <p>The Method object for JDK1.4 getCause.</p>
   */
  private static final Method THROWABLE_CAUSE_METHOD;
  static {
      Method getCauseMethod;
      try {
          getCauseMethod = Throwable.class.getMethod("getCause", (Class[])null);
      } catch (Exception e) {
          getCauseMethod = null;
      }
      THROWABLE_CAUSE_METHOD = getCauseMethod;
  }
  
  /**
   * <p>Checks if the Throwable class has a <code>getCause</code> method.</p>
   * 
   * <p>This is true for JDK 1.4 and above.</p>
   * 
   * @return true if Throwable is nestable
   * @since 2.0
   */
  public static boolean isThrowableNested() {
      return THROWABLE_CAUSE_METHOD != null;
  }

  /**
   * <p>Introspects the <code>Throwable</code> to obtain the cause.</p>
   * 
   * <p>The method searches for methods with specific names that return a 
   * <code>Throwable</code> object. This will pick up most wrapping exceptions,
   * including those from JDK 1.4, and</p>
   *
   * <p>The default list searched for are:</p>
   * <ul>
   *  <li><code>getCause()</code></li>
   *  <li><code>getNextException()</code></li>
   *  <li><code>getTargetException()</code></li>
   *  <li><code>getException()</code></li>
   *  <li><code>getSourceException()</code></li>
   *  <li><code>getRootCause()</code></li>
   *  <li><code>getCausedByException()</code></li>
   *  <li><code>getNested()</code></li>
   * </ul>
   * 
   * <p>In the absence of any such method, the object is inspected for a
   * <code>detail</code> field assignable to a <code>Throwable</code>.</p>
   * 
   * <p>If none of the above is found, returns <code>null</code>.</p>
   *
   * @param throwable  the throwable to introspect for a cause, may be null
   * @return the cause of the <code>Throwable</code>,
   *  <code>null</code> if none found or null throwable input
   * @since 1.0
   */
  public static Throwable getCause(Throwable throwable) {
      return getCause(throwable, CAUSE_METHOD_NAMES);
  }

  /**
   * <p>Introspects the <code>Throwable</code> to obtain the cause.</p>
   * 
   * <ol>
   * <li>Try known exception types.</li>
   * <li>Try the supplied array of method names.</li>
   * <li>Try the field 'detail'.</li>
   * </ol>
   * 
   * <p>A <code>null</code> set of method names means use the default set.
   * A <code>null</code> in the set of method names will be ignored.</p>
   *
   * @param throwable  the throwable to introspect for a cause, may be null
   * @param methodNames  the method names, null treated as default set
   * @return the cause of the <code>Throwable</code>,
   *  <code>null</code> if none found or null throwable input
   * @since 1.0
   */
  public static Throwable getCause(Throwable throwable, String[] methodNames) {
      if (throwable == null) {
          return null;
      }
      Throwable cause = getCauseUsingWellKnownTypes(throwable);
      if (cause == null) {
          if (methodNames == null) {
              methodNames = CAUSE_METHOD_NAMES;
          }
          for (int i = 0; i < methodNames.length; i++) {
              String methodName = methodNames[i];
              if (methodName != null) {
                  cause = getCauseUsingMethodName(throwable, methodName);
                  if (cause != null) {
                      break;
                  }
              }
          }

          if (cause == null) {
              cause = getCauseUsingFieldName(throwable, "detail");
          }
      }
      return cause;
  }

  /**
   * <p>Finds a <code>Throwable</code> by method name.</p>
   * 
   * @param throwable  the exception to examine
   * @param methodName  the name of the method to find and invoke
   * @return the wrapped exception, or <code>null</code> if not found
   */
  private static Throwable getCauseUsingMethodName(Throwable throwable, String methodName) {
      Method method = null;
      try {
          method = throwable.getClass().getMethod(methodName, (Class[])null);
      } catch (NoSuchMethodException ignored) {
      } catch (SecurityException ignored) {
      }

      if (method != null && Throwable.class.isAssignableFrom(method.getReturnType())) {
          try {
              return (Throwable) method.invoke(throwable, EMPTY_OBJECT_ARRAY);
          } catch (IllegalAccessException ignored) {
          } catch (IllegalArgumentException ignored) {
          } catch (InvocationTargetException ignored) {
          }
      }
      return null;
  }

  /**
   * <p>Finds a <code>Throwable</code> by field name.</p>
   * 
   * @param throwable  the exception to examine
   * @param fieldName  the name of the attribute to examine
   * @return the wrapped exception, or <code>null</code> if not found
   */
  private static Throwable getCauseUsingFieldName(Throwable throwable, String fieldName) {
      Field field = null;
      try {
          field = throwable.getClass().getField(fieldName);
      } catch (NoSuchFieldException ignored) {
      } catch (SecurityException ignored) {
      }

      if (field != null && Throwable.class.isAssignableFrom(field.getType())) {
          try {
              return (Throwable) field.get(throwable);
          } catch (IllegalAccessException ignored) {
          } catch (IllegalArgumentException ignored) {
          }
      }
      return null;
  }

  /**
   * <p>Finds a <code>Throwable</code> for known types.</p>
   * 
   * <p>Uses <code>instanceof</code> checks to examine the exception,
   * looking for well known types which could contain chained or
   * wrapped exceptions.</p>
   *
   * @param throwable  the exception to examine
   * @return the wrapped exception, or <code>null</code> if not found
   */
  private static Throwable getCauseUsingWellKnownTypes(Throwable throwable) {
      if (throwable instanceof SQLException) {
          return ((SQLException) throwable).getNextException();
      } else if (throwable instanceof InvocationTargetException) {
          return ((InvocationTargetException) throwable).getTargetException();
      } else {
          return null;
      }
  }

  /**
   * An empty immutable <code>Object</code> array.
   */
  public static final Object[] EMPTY_OBJECT_ARRAY = new Object[0];
  
  /** 
   * from a command line arg, get the key.  e.g. if input is --whatever=something
   * then key is whatever, value is something 
   * @param option string such as "--key=value"
   * @return the key portion of the argument
   */
  public static String argKey(String option) {
    int equalsIndex = option.indexOf("=");
    if (equalsIndex == -1) {
      throw new RuntimeException("Invalid option: " + option + ", it should look like: --someOption=someValue");
    }
    String key = option.substring(0,equalsIndex);
    if (!key.startsWith("--")) {
      throw new RuntimeException("Invalid option: " + option + ", it should look like: --someOption=someValue");
    }
    key = key.substring(2);
    return key;
  }

  /** 
   * from a command line arg, get the key.  e.g. if input is --whatever=something
   * then key is whatever, value is something 
   * @param option The option string such as "--someOption=value"
   * @return the value of the option
   */
  public static String argValue(String option) {
    int equalsIndex = option.indexOf("=");
    if (equalsIndex == -1) {
      throw new RuntimeException("Invalid option: " + option + ", it should look like: --someOption=someValue");
    }
    String value = option.substring(equalsIndex+1, option.length());
    return value;
  }
  
  /** add an option: --whatever=val   to a map of options where --whatever is key, and val is value 
   * @param args Arguments array
   * @return the map
   */
  public static Map<String, String> argMap(String[] args) {
    
    Map<String, String> result = new LinkedHashMap<String, String>();

    for (String arg : nonNull(args,String.class)) {
      String key = argKey(arg);
      String value = argValue(arg);
      if (result.containsKey(key)) {
        throw new RuntimeException("Passing key twice: " + key);
      }
      result.put(key, value);
    }
    
    return result;
  }
  
  /**
   * get the value from the argMap, throw exception if not there and required
   * @param argMap map of argument key/values
   * @param argMapNotUsed keeps track of unused arguments
   * @param key the key to lookup
   * @param required whether or not the key is required to be present
   * @return the value or null or exception
   */
  public static String argMapString(Map<String, String> argMap, Map<String, String> argMapNotUsed, 
      String key, boolean required) {

    if (argMap.containsKey(key)) {
      
      //keep track that this is gone
      argMapNotUsed.remove(key);
      
      return argMap.get(key);
    }
    if (required) {
      throw new RuntimeException("Argument '--" + key + "' is required, but not specified.  e.g. --" + key + "=value");
    }
    return null;

  }
  
  /**
   * get the value from the argMap, throw exception if not there and required
   * @param argMap map of argument key/values
   * @param argMapNotUsed keeps track of unused arguments
   * @param key the key to lookup
   * @param required whether or not the key is required to be present
   * @param defaultValue the value to use when the key lookup results in blank / null
   * @return the value or null or exception
   */
  public static boolean argMapBoolean(Map<String, String> argMap, Map<String, String> argMapNotUsed, 
      String key, boolean required, boolean defaultValue) {
    String argString = argMapString(argMap, argMapNotUsed, key, required);

    if (isBlank(argString) && required) {
      throw new RuntimeException("Argument '--" + key + "' is required, but not specified.  e.g. --" + key + "=true");
    }
    return booleanValue(argString, defaultValue);
  }
  
  /**
   * get the value from the argMap, throw exception if not there and required
   * @param argMap map of argument key/values
   * @param argMapNotUsed keeps track of unused arguments
   * @param key the key to lookup
   * @return the value or null or exception
   */
  public static Timestamp argMapTimestamp(Map<String, String> argMap, Map<String, String> argMapNotUsed, 
      String key) {
    String argString = argMapString(argMap, argMapNotUsed, key, false);
    if (isBlank(argString)) {
      return null;
    }
    Date date = stringToDate2(argString);
    return new Timestamp(date.getTime());
  }
  
  /**
   * get the value from the argMap
   * @param argMap map of argument key/values
   * @param argMapNotUsed keeps track of unused arguments
   * @param key the key to lookup
   * @return the value or null or exception
   */
  public static Boolean argMapBoolean(Map<String, String> argMap, Map<String, String> argMapNotUsed, 
      String key) {
    String argString = argMapString(argMap, argMapNotUsed, key, false);

    return booleanObjectValue(argString);
  }
  
  /**
   * get the set from comma separated from the argMap, throw exception if not there and required
   * @param argMap map of argument key/values
   * @param argMapNotUsed keeps track of unused arguments
   * @param key the key to lookup
   * @param required whether or not the key is required to be present
   * @return the value or null or exception
   */
  public static Set<String> argMapSet(Map<String, String> argMap, Map<String, String> argMapNotUsed, 
      String key, boolean required) {
    List<String> list = argMapList(argMap, argMapNotUsed, key, required);
    return list == null ? null : new LinkedHashSet(list);
  }
  
  /**
   * get the list from comma separated from the argMap, throw exception if not there and required
   * @param argMap map of argument key/values
   * @param argMapNotUsed keeps track of unused arguments
   * @param key the key to lookup
   * @param required whether or not the key is required to be present
   * @return the value or null or exception
   */
  public static List<String> argMapList(Map<String, String> argMap, Map<String, String> argMapNotUsed, 
      String key, boolean required) {
    String argString = argMapString(argMap, argMapNotUsed, key, required);
    if (isBlank(argString)) {
      return null;
    }
    return splitTrimToList(argString, ",");
  }
  
  /**
   * get the list from comma separated from the argMap, throw exception if not there and required
   * @param argMap map of argument key/values
   * @param argMapNotUsed keeps track of unused arguments
   * @param key the key to lookup
   * @param required whether or not the key is required to be present
   * @return the value or null or exception
   */
  public static List<String> argMapFileList(Map<String, String> argMap, Map<String, String> argMapNotUsed, 
      String key, boolean required) {
    String argString = argMapString(argMap, argMapNotUsed, key, required);
    if (isBlank(argString)) {
      return null;
    }
    //read from file
    File file = new File(argString);
    try {
      //do this by regex, since we dont know what platform we are on
      String listString = readFileIntoString(file);
      String[] array = listString.split("\\s+");
      List<String> list = new ArrayList<String>();
      for (String string : array) {
        //dont know if any here will be blank or whatnot
        if (!isBlank(string)) {
          //should already be trimmed, but just in case
          list.add(trim(string));
        }
      }
      return list;
    } catch (Exception e) {
      throw new RuntimeException("Error reading file: '" 
          + fileCanonicalPath(file) + "' from command line arg: " + key, e );
    }
  }
  
  /**
   * Copy bytes from an <code>InputStream</code> to chars on a
   * <code>Writer</code> using the default character encoding of the platform.
   * <p>
   * This method buffers the input internally, so there is no need to use a
   * <code>BufferedInputStream</code>.
   * <p>
   * This method uses {@link InputStreamReader}.
   *
   * @param input  the <code>InputStream</code> to read from
   * @param output  the <code>Writer</code> to write to
   * @throws NullPointerException if the input or output is null
   * @throws IOException if an I/O error occurs
   * @since Commons IO 1.1
   */
  public static void copy(InputStream input, Writer output)
          throws IOException {
      String charsetName = "UTF-8";
      InputStreamReader in = new InputStreamReader(input, charsetName);
      copy(in, output);
  }
  
  /**
   * Copy bytes from an <code>InputStream</code> to an
   * <code>OutputStream</code>.
   * <p>
   * This method buffers the input internally, so there is no need to use a
   * <code>BufferedInputStream</code>.
   * <p>
   * Large streams (over 2GB) will return a bytes copied value of
   * <code>-1</code> after the copy has completed since the correct
   * number of bytes cannot be returned as an int. For large streams
   * use the <code>copyLarge(InputStream, OutputStream)</code> method.
   * 
   * @param input  the <code>InputStream</code> to read from
   * @param output  the <code>OutputStream</code> to write to
   * @return the number of bytes copied
   * @throws NullPointerException if the input or output is null
   * @throws IOException if an I/O error occurs
   * @throws ArithmeticException if the byte count is too large
   * @since Commons IO 1.1
   */
  public static int copy(InputStream input, OutputStream output) throws IOException {
      long count = copyLarge(input, output);
      if (count > Integer.MAX_VALUE) {
          return -1;
      }
      return (int) count;
  }

  /**
   * Copy bytes from a large (over 2GB) <code>InputStream</code> to an
   * <code>OutputStream</code>.
   * <p>
   * This method buffers the input internally, so there is no need to use a
   * <code>BufferedInputStream</code>.
   * 
   * @param input  the <code>InputStream</code> to read from
   * @param output  the <code>OutputStream</code> to write to
   * @return the number of bytes copied
   * @throws NullPointerException if the input or output is null
   * @throws IOException if an I/O error occurs
   * @since Commons IO 1.3
   */
  public static long copyLarge(InputStream input, OutputStream output)
          throws IOException {
      byte[] buffer = new byte[DEFAULT_BUFFER_SIZE];
      long count = 0;
      int n = 0;
      while (-1 != (n = input.read(buffer))) {
          output.write(buffer, 0, n);
          count += n;
      }
      return count;
  }

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

  /**
   * retrieve a password from stdin
   * @param dontMask when true, the user's typing will appear on the screen
   * @param prompt to print to user
   * @return the password
   */
  public static String retrievePasswordFromStdin(boolean dontMask, String prompt) {
    String passwordString = null;

    if (dontMask) {

      System.out.print(prompt);
      //  open up standard input 
      BufferedReader br = new BufferedReader(new InputStreamReader(System.in)); 

      //  read the username from the command-line; need to use try/catch with the 
      //  readLine() method 
      try { 
         passwordString = br.readLine(); 
      } catch (IOException ioe) { 
         System.out.println("IO error! " + getFullStackTrace(ioe));
         System.exit(1); 
      } 

    } else {
      char password[] = null;
      try {
        password = retrievePasswordFromStdin(System.in, prompt);
      } catch (IOException ioe) {
        ioe.printStackTrace();
      }
      passwordString = String.valueOf(password);
    } 
    return passwordString;
    
  }

  /**
   * @param in stream to be used (e.g. System.in)
   * @param prompt The prompt to display to the user.
   * @return The password as entered by the user.
   * @throws IOException when there was a problem with the input stream
   */
  public static final char[] retrievePasswordFromStdin(InputStream in, String prompt) throws IOException {
    MaskingThread maskingthread = new MaskingThread(prompt);

    Thread thread = new Thread(maskingthread);
    thread.start();

    char[] lineBuffer;
    char[] buf;

    buf = lineBuffer = new char[128];

    int room = buf.length;
    int offset = 0;
    int c;

    loop: while (true) {
      switch (c = in.read()) {
        case -1:
        case '\n':
          break loop;

        case '\r':
          int c2 = in.read();
          if ((c2 != '\n') && (c2 != -1)) {
            if (!(in instanceof PushbackInputStream)) {
              in = new PushbackInputStream(in);
            }
            ((PushbackInputStream) in).unread(c2);
          } else {
            break loop;
          }

        default:
          if (--room < 0) {
            buf = new char[offset + 128];
            room = buf.length - offset - 1;
            System.arraycopy(lineBuffer, 0, buf, 0, offset);
            Arrays.fill(lineBuffer, ' ');
            lineBuffer = buf;
          }
          buf[offset++] = (char) c;
          break;
      }
    }
    maskingthread.stopMasking();
    if (offset == 0) {
      return null;
    }
    char[] ret = new char[offset];
    System.arraycopy(buf, 0, ret, 0, offset);
    Arrays.fill(buf, ' ');
    return ret;
  }

  /**
   * thread to mask input
   */
  static class MaskingThread extends Thread {

    /** stop */
    private volatile boolean stop;

    /** echo char, this doesnt work correctly, so make a space so people dont notice...  
     * prints out too many */
    private char echochar = ' ';

    /**
     *@param prompt The prompt displayed to the user
     */
    public MaskingThread(String prompt) {
      System.out.print(prompt);
    }

    /**
     * Begin masking until asked to stop.
     */
    @Override
    public void run() {

      int priority = Thread.currentThread().getPriority();
      Thread.currentThread().setPriority(Thread.MAX_PRIORITY);

      try {
        this.stop = true;
        while (this.stop) {
          System.out.print("\010" + this.echochar);
          try {
            // attempt masking at this rate
            Thread.sleep(1);
          } catch (InterruptedException iex) {
            Thread.currentThread().interrupt();
            return;
          }
        }
      } finally { // restore the original priority
        Thread.currentThread().setPriority(priority);
      }
    }

    /**
     * Instruct the thread to stop masking.
     */
    public void stopMasking() {
      this.stop = false;
    }
  }

  /**
   * make sure a value exists in properties
   * @param resourceName the resource name
   * @param properties the properties
   * @param overrideMap a map overriding some properties, used in testing or debug
   * @param key the property key
   * @param exceptionOnError when true, throw an exception if property is not the proper value type 
   * @return true if ok, false if not
   */
  public static boolean propertyValidateValueRequired(String resourceName, Properties properties, 
      Map<String, String> overrideMap, String key, boolean exceptionOnError) {
    
    Map<String, String> threadLocalMap = propertiesThreadLocalOverrideMap(resourceName);

    String value = propertiesValue(properties, threadLocalMap, overrideMap, key);

    if (!isBlank(value)) {
      return true;
    }
    String error = "Cant find property " + key + " in resource: " + resourceName + ", it is required";
    
    if (exceptionOnError) {
      throw new RuntimeException(error);
    }
    
    System.err.println("Grouper error: " + error);
    return false;
  }

  /**
   * make sure a value is boolean in properties
   * @param resourceName the resource name
   * @param properties the properties
   * @param overrideMap a map overriding some properties, used in testing or debug
   * @param key the property key
   * @param required whether or not a value is required for the key
   * @param exceptionOnError when true, throw an exception if property is not the proper value type 
   * @return true if ok, false if not
   */
  public static boolean propertyValidateValueBoolean(String resourceName, Properties properties, 
      Map<String, String> overrideMap, String key, 
      boolean required, boolean exceptionOnError) {
    
    if (required && !propertyValidateValueRequired(resourceName, properties, 
        overrideMap, key, exceptionOnError)) {
      return false;
    }
  
    Map<String, String> threadLocalMap = propertiesThreadLocalOverrideMap(resourceName);

    String value = propertiesValue(properties, threadLocalMap, overrideMap, key);
    //maybe ok not there
    if (!required && isBlank(value)) {
      return true;
    }
    try {
      booleanValue(value);
      return true;
    } catch (Exception e) {
      
    }
    String error = "Expecting true or false property " + key + " in resource: " + resourceName + ", but is '" + value + "'";
    if (exceptionOnError) {
      throw new RuntimeException(error);
    }
    System.err.println("Grouper error: " + error);
    return false;
  }

  
  /**
   * make sure a value is int in properties
   * @param resourceName the resource name
   * @param properties the properties
   * @param overrideMap a map overriding some properties, used in testing or debug
   * @param key the property key
   * @param required whether or not a value is required for the key
   * @param exceptionOnError when true, throw an exception if property is not the proper value type 
   * @return true if ok, false if not
   */
  public static boolean propertyValidateValueInt(String resourceName, Properties properties, 
      Map<String, String> overrideMap, String key, 
      boolean required, boolean exceptionOnError) {
    
    if (required && !propertyValidateValueRequired(resourceName, properties, 
        overrideMap, key, exceptionOnError)) {
      return false;
    }
  
    Map<String, String> threadLocalMap = propertiesThreadLocalOverrideMap(resourceName);
    
    String value = propertiesValue(properties, threadLocalMap, overrideMap, key);
    //maybe ok not there
    if (!required && isBlank(value)) {
      return true;
    }
    try {
      intValue(value);
      return true;
    } catch (Exception e) {
      
    }
    String error = "Expecting integer property " + key + " in resource: " + resourceName + ", but is '" + value + "'";
    if (exceptionOnError) {
      throw new RuntimeException(error);
    }
    System.err.println("Grouper error: " + error);
    return false;
  }

  /**
   * make sure a property is a class of a certain type
   * @param resourceName the property resource name
   * @param properties the set of properties 
   * @param overrideMap for testing, to override some properties values
   * @param key the lookup key
   * @param classType the desired class type
   * @param required whether or not a value is required
   * @param exceptionOnError throw an exception when there is an error
   * @return true if ok
   */
  public static boolean propertyValidateValueClass(String resourceName, Properties properties, 
      Map<String, String> overrideMap, String key, Class<?> classType, boolean required, boolean exceptionOnError) {
  
    if (required && !propertyValidateValueRequired(resourceName, properties, 
        overrideMap, key, exceptionOnError)) {
      return false;
    }
    String value = propertiesValue(properties, overrideMap, key);
  
    //maybe ok not there
    if (!required && isBlank(value)) {
      return true;
    }
    
    String extraError = "";
    try {
      
      
      Class<?> theClass = forName(value);
      if (classType.isAssignableFrom(theClass)) {
        return true;
      }
      extraError = " does not derive from class: " + classType.getSimpleName();
      
    } catch (Exception e) {
      extraError = ", " + getFullStackTrace(e);
    }
    String error = "Cant process property " + key + " in resource: " + resourceName + ", the current" +
        " value is '" + value + "', which should be of type: " 
        + classType.getName() + extraError;
    if (exceptionOnError) {
      throw new RuntimeException(error);
    }
    System.err.println("Grouper error: " + error);
    return false;

  }

  /**
   * <p>Strips any of a set of characters from the start of a String.</p>
   *
   * <p>A <code>null</code> input String returns <code>null</code>.
   * An empty string ("") input returns the empty string.</p>
   *
   * <p>If the stripChars String is <code>null</code>, whitespace is
   * stripped as defined by {@link Character#isWhitespace(char)}.</p>
   *
   * <pre>
   * StringUtils.stripStart(null, *)          = null
   * StringUtils.stripStart("", *)            = ""
   * StringUtils.stripStart("abc", "")        = "abc"
   * StringUtils.stripStart("abc", null)      = "abc"
   * StringUtils.stripStart("  abc", null)    = "abc"
   * StringUtils.stripStart("abc  ", null)    = "abc  "
   * StringUtils.stripStart(" abc ", null)    = "abc "
   * StringUtils.stripStart("yxabc  ", "xyz") = "abc  "
   * </pre>
   *
   * @param str  the String to remove characters from, may be null
   * @param stripChars  the characters to remove, null treated as whitespace
   * @return the stripped String, <code>null</code> if null String input
   */
  public static String stripStart(String str, String stripChars) {
    int strLen;
    if (str == null || (strLen = str.length()) == 0) {
      return str;
    }
    int start = 0;
    if (stripChars == null) {
      while ((start != strLen) && Character.isWhitespace(str.charAt(start))) {
        start++;
      }
    } else if (stripChars.length() == 0) {
      return str;
    } else {
      while ((start != strLen) && (stripChars.indexOf(str.charAt(start)) != -1)) {
        start++;
      }
    }
    return str.substring(start);
  }

  /**
   * <p>Strips any of a set of characters from the end of a String.</p>
   *
   * <p>A <code>null</code> input String returns <code>null</code>.
   * An empty string ("") input returns the empty string.</p>
   *
   * <p>If the stripChars String is <code>null</code>, whitespace is
   * stripped as defined by {@link Character#isWhitespace(char)}.</p>
   *
   * <pre>
   * StringUtils.stripEnd(null, *)          = null
   * StringUtils.stripEnd("", *)            = ""
   * StringUtils.stripEnd("abc", "")        = "abc"
   * StringUtils.stripEnd("abc", null)      = "abc"
   * StringUtils.stripEnd("  abc", null)    = "  abc"
   * StringUtils.stripEnd("abc  ", null)    = "abc"
   * StringUtils.stripEnd(" abc ", null)    = " abc"
   * StringUtils.stripEnd("  abcyx", "xyz") = "  abc"
   * </pre>
   *
   * @param str  the String to remove characters from, may be null
   * @param stripChars  the characters to remove, null treated as whitespace
   * @return the stripped String, <code>null</code> if null String input
   */
  public static String stripEnd(String str, String stripChars) {
    int end;
    if (str == null || (end = str.length()) == 0) {
      return str;
    }

    if (stripChars == null) {
      while ((end != 0) && Character.isWhitespace(str.charAt(end - 1))) {
        end--;
      }
    } else if (stripChars.length() == 0) {
      return str;
    } else {
      while ((end != 0) && (stripChars.indexOf(str.charAt(end - 1)) != -1)) {
        end--;
      }
    }
    return str.substring(0, end);
  }

  /**
   * The empty String <code>""</code>.
   * @since 2.0
   */
  public static final String EMPTY = "";

  /**
   * Represents a failed index search.
   * @since 2.1
   */
  public static final int INDEX_NOT_FOUND = -1;

  /**
   * <p>The maximum size to which the padding constant(s) can expand.</p>
   */
  private static final int PAD_LIMIT = 8192;

  /**
   * <p>An array of <code>String</code>s used for padding.</p>
   *
   * <p>Used for efficient space padding. The length of each String expands as needed.</p>
   */
  private static final String[] PADDING = new String[Character.MAX_VALUE];

  static {
    // space padding is most common, start with 64 chars
    PADDING[32] = "                                                                ";
  }

  /**
   * <p>Repeat a String <code>repeat</code> times to form a
   * new String.</p>
   *
   * <pre>
   * StringUtils.repeat(null, 2) = null
   * StringUtils.repeat("", 0)   = ""
   * StringUtils.repeat("", 2)   = ""
   * StringUtils.repeat("a", 3)  = "aaa"
   * StringUtils.repeat("ab", 2) = "abab"
   * StringUtils.repeat("a", -2) = ""
   * </pre>
   *
   * @param str  the String to repeat, may be null
   * @param repeat  number of times to repeat str, negative treated as zero
   * @return a new String consisting of the original String repeated,
   *  <code>null</code> if null String input
   */
  public static String repeat(String str, int repeat) {
    // Performance tuned for 2.0 (JDK1.4)

    if (str == null) {
      return null;
    }
    if (repeat <= 0) {
      return EMPTY;
    }
    int inputLength = str.length();
    if (repeat == 1 || inputLength == 0) {
      return str;
    }
    if (inputLength == 1 && repeat <= PAD_LIMIT) {
      return padding(repeat, str.charAt(0));
    }

    int outputLength = inputLength * repeat;
    switch (inputLength) {
      case 1:
        char ch = str.charAt(0);
        char[] output1 = new char[outputLength];
        for (int i = repeat - 1; i >= 0; i--) {
          output1[i] = ch;
        }
        return new String(output1);
      case 2:
        char ch0 = str.charAt(0);
        char ch1 = str.charAt(1);
        char[] output2 = new char[outputLength];
        for (int i = repeat * 2 - 2; i >= 0; i--, i--) {
          output2[i] = ch0;
          output2[i + 1] = ch1;
        }
        return new String(output2);
      default:
        StringBuffer buf = new StringBuffer(outputLength);
        for (int i = 0; i < repeat; i++) {
          buf.append(str);
        }
        return buf.toString();
    }
  }

  /**
   * <p>Returns padding using the specified delimiter repeated
   * to a given length.</p>
   *
   * <pre>
   * StringUtils.padding(0, 'e')  = ""
   * StringUtils.padding(3, 'e')  = "eee"
   * StringUtils.padding(-2, 'e') = IndexOutOfBoundsException
   * </pre>
   *
   * @param repeat  number of times to repeat delim
   * @param padChar  character to repeat
   * @return String with repeated character
   * @throws IndexOutOfBoundsException if <code>repeat &lt; 0</code>
   */
  private static String padding(int repeat, char padChar) {
    // be careful of synchronization in this method
    // we are assuming that get and set from an array index is atomic
    String pad = PADDING[padChar];
    if (pad == null) {
      pad = String.valueOf(padChar);
    }
    while (pad.length() < repeat) {
      pad = pad.concat(pad);
    }
    PADDING[padChar] = pad;
    return pad.substring(0, repeat);
  }

  /**
   * <p>Right pad a String with spaces (' ').</p>
   *
   * <p>The String is padded to the size of <code>size</code>.</p>
   *
   * <pre>
   * StringUtils.rightPad(null, *)   = null
   * StringUtils.rightPad("", 3)     = "   "
   * StringUtils.rightPad("bat", 3)  = "bat"
   * StringUtils.rightPad("bat", 5)  = "bat  "
   * StringUtils.rightPad("bat", 1)  = "bat"
   * StringUtils.rightPad("bat", -1) = "bat"
   * </pre>
   *
   * @param str  the String to pad out, may be null
   * @param size  the size to pad to
   * @return right padded String or original String if no padding is necessary,
   *  <code>null</code> if null String input
   */
  public static String rightPad(String str, int size) {
    return rightPad(str, size, ' ');
  }

  /**
   * <p>Right pad a String with a specified character.</p>
   *
   * <p>The String is padded to the size of <code>size</code>.</p>
   *
   * <pre>
   * StringUtils.rightPad(null, *, *)     = null
   * StringUtils.rightPad("", 3, 'z')     = "zzz"
   * StringUtils.rightPad("bat", 3, 'z')  = "bat"
   * StringUtils.rightPad("bat", 5, 'z')  = "batzz"
   * StringUtils.rightPad("bat", 1, 'z')  = "bat"
   * StringUtils.rightPad("bat", -1, 'z') = "bat"
   * </pre>
   *
   * @param str  the String to pad out, may be null
   * @param size  the size to pad to
   * @param padChar  the character to pad with
   * @return right padded String or original String if no padding is necessary,
   *  <code>null</code> if null String input
   * @since 2.0
   */
  public static String rightPad(String str, int size, char padChar) {
    if (str == null) {
      return null;
    }
    int pads = size - str.length();
    if (pads <= 0) {
      return str; // returns original String when possible
    }
    if (pads > PAD_LIMIT) {
      return rightPad(str, size, String.valueOf(padChar));
    }
    return str.concat(padding(pads, padChar));
  }

  /**
   * <p>Right pad a String with a specified String.</p>
   *
   * <p>The String is padded to the size of <code>size</code>.</p>
   *
   * <pre>
   * StringUtils.rightPad(null, *, *)      = null
   * StringUtils.rightPad("", 3, "z")      = "zzz"
   * StringUtils.rightPad("bat", 3, "yz")  = "bat"
   * StringUtils.rightPad("bat", 5, "yz")  = "batyz"
   * StringUtils.rightPad("bat", 8, "yz")  = "batyzyzy"
   * StringUtils.rightPad("bat", 1, "yz")  = "bat"
   * StringUtils.rightPad("bat", -1, "yz") = "bat"
   * StringUtils.rightPad("bat", 5, null)  = "bat  "
   * StringUtils.rightPad("bat", 5, "")    = "bat  "
   * </pre>
   *
   * @param str  the String to pad out, may be null
   * @param size  the size to pad to
   * @param padStr  the String to pad with, null or empty treated as single space
   * @return right padded String or original String if no padding is necessary,
   *  <code>null</code> if null String input
   */
  public static String rightPad(String str, int size, String padStr) {
    if (str == null) {
      return null;
    }
    if (isEmpty(padStr)) {
      padStr = " ";
    }
    int padLen = padStr.length();
    int strLen = str.length();
    int pads = size - strLen;
    if (pads <= 0) {
      return str; // returns original String when possible
    }
    if (padLen == 1 && pads <= PAD_LIMIT) {
      return rightPad(str, size, padStr.charAt(0));
    }

    if (pads == padLen) {
      return str.concat(padStr);
    } else if (pads < padLen) {
      return str.concat(padStr.substring(0, pads));
    } else {
      char[] padding = new char[pads];
      char[] padChars = padStr.toCharArray();
      for (int i = 0; i < pads; i++) {
        padding[i] = padChars[i % padLen];
      }
      return str.concat(new String(padding));
    }
  }

  /**
   * <p>Left pad a String with spaces (' ').</p>
   *
   * <p>The String is padded to the size of <code>size</code>.</p>
   *
   * <pre>
   * StringUtils.leftPad(null, *)   = null
   * StringUtils.leftPad("", 3)     = "   "
   * StringUtils.leftPad("bat", 3)  = "bat"
   * StringUtils.leftPad("bat", 5)  = "  bat"
   * StringUtils.leftPad("bat", 1)  = "bat"
   * StringUtils.leftPad("bat", -1) = "bat"
   * </pre>
   *
   * @param str  the String to pad out, may be null
   * @param size  the size to pad to
   * @return left padded String or original String if no padding is necessary,
   *  <code>null</code> if null String input
   */
  public static String leftPad(String str, int size) {
    return leftPad(str, size, ' ');
  }

  /**
   * <p>Left pad a String with a specified character.</p>
   *
   * <p>Pad to a size of <code>size</code>.</p>
   *
   * <pre>
   * StringUtils.leftPad(null, *, *)     = null
   * StringUtils.leftPad("", 3, 'z')     = "zzz"
   * StringUtils.leftPad("bat", 3, 'z')  = "bat"
   * StringUtils.leftPad("bat", 5, 'z')  = "zzbat"
   * StringUtils.leftPad("bat", 1, 'z')  = "bat"
   * StringUtils.leftPad("bat", -1, 'z') = "bat"
   * </pre>
   *
   * @param str  the String to pad out, may be null
   * @param size  the size to pad to
   * @param padChar  the character to pad with
   * @return left padded String or original String if no padding is necessary,
   *  <code>null</code> if null String input
   * @since 2.0
   */
  public static String leftPad(String str, int size, char padChar) {
    if (str == null) {
      return null;
    }
    int pads = size - str.length();
    if (pads <= 0) {
      return str; // returns original String when possible
    }
    if (pads > PAD_LIMIT) {
      return leftPad(str, size, String.valueOf(padChar));
    }
    return padding(pads, padChar).concat(str);
  }

  /**
   * <p>Left pad a String with a specified String.</p>
   *
   * <p>Pad to a size of <code>size</code>.</p>
   *
   * <pre>
   * StringUtils.leftPad(null, *, *)      = null
   * StringUtils.leftPad("", 3, "z")      = "zzz"
   * StringUtils.leftPad("bat", 3, "yz")  = "bat"
   * StringUtils.leftPad("bat", 5, "yz")  = "yzbat"
   * StringUtils.leftPad("bat", 8, "yz")  = "yzyzybat"
   * StringUtils.leftPad("bat", 1, "yz")  = "bat"
   * StringUtils.leftPad("bat", -1, "yz") = "bat"
   * StringUtils.leftPad("bat", 5, null)  = "  bat"
   * StringUtils.leftPad("bat", 5, "")    = "  bat"
   * </pre>
   *
   * @param str  the String to pad out, may be null
   * @param size  the size to pad to
   * @param padStr  the String to pad with, null or empty treated as single space
   * @return left padded String or original String if no padding is necessary,
   *  <code>null</code> if null String input
   */
  public static String leftPad(String str, int size, String padStr) {
    if (str == null) {
      return null;
    }
    if (isEmpty(padStr)) {
      padStr = " ";
    }
    int padLen = padStr.length();
    int strLen = str.length();
    int pads = size - strLen;
    if (pads <= 0) {
      return str; // returns original String when possible
    }
    if (padLen == 1 && pads <= PAD_LIMIT) {
      return leftPad(str, size, padStr.charAt(0));
    }

    if (pads == padLen) {
      return padStr.concat(str);
    } else if (pads < padLen) {
      return padStr.substring(0, pads).concat(str);
    } else {
      char[] padding = new char[pads];
      char[] padChars = padStr.toCharArray();
      for (int i = 0; i < pads; i++) {
        padding[i] = padChars[i % padLen];
      }
      return new String(padding).concat(str);
    }
  }

  /**
   * convert an exception to a runtime exception
   * @param e the exception to convert
   */
  public static void convertToRuntimeException(Exception e) {
    if (e instanceof RuntimeException) {
      throw (RuntimeException)e;
    }
    throw new RuntimeException(e.getMessage(), e);
  }

  /**
   * <p>Gets the substring before the first occurrence of a separator.
   * The separator is not returned.</p>
   *
   * <p>A <code>null</code> string input will return <code>null</code>.
   * An empty ("") string input will return the empty string.
   * A <code>null</code> separator will return the input string.</p>
   *
   * <pre>
   * StringUtils.substringBefore(null, *)      = null
   * StringUtils.substringBefore("", *)        = ""
   * StringUtils.substringBefore("abc", "a")   = ""
   * StringUtils.substringBefore("abcba", "b") = "a"
   * StringUtils.substringBefore("abc", "c")   = "ab"
   * StringUtils.substringBefore("abc", "d")   = "abc"
   * StringUtils.substringBefore("abc", "")    = ""
   * StringUtils.substringBefore("abc", null)  = "abc"
   * </pre>
   *
   * @param str  the String to get a substring from, may be null
   * @param separator  the String to search for, may be null
   * @return the substring before the first occurrence of the separator,
   *  <code>null</code> if null String input
   * @since 2.0
   */
  public static String substringBefore(String str, String separator) {
    if (isEmpty(str) || separator == null) {
      return str;
    }
    if (separator.length() == 0) {
      return EMPTY;
    }
    int pos = str.indexOf(separator);
    if (pos == -1) {
      return str;
    }
    return str.substring(0, pos);
  }

  /**
   * <p>Gets the substring after the first occurrence of a separator.
   * The separator is not returned.</p>
   *
   * <p>A <code>null</code> string input will return <code>null</code>.
   * An empty ("") string input will return the empty string.
   * A <code>null</code> separator will return the empty string if the
   * input string is not <code>null</code>.</p>
   *
   * <pre>
   * StringUtils.substringAfter(null, *)      = null
   * StringUtils.substringAfter("", *)        = ""
   * StringUtils.substringAfter(*, null)      = ""
   * StringUtils.substringAfter("abc", "a")   = "bc"
   * StringUtils.substringAfter("abcba", "b") = "cba"
   * StringUtils.substringAfter("abc", "c")   = ""
   * StringUtils.substringAfter("abc", "d")   = ""
   * StringUtils.substringAfter("abc", "")    = "abc"
   * </pre>
   *
   * @param str  the String to get a substring from, may be null
   * @param separator  the String to search for, may be null
   * @return the substring after the first occurrence of the separator,
   *  <code>null</code> if null String input
   * @since 2.0
   */
  public static String substringAfter(String str, String separator) {
    if (isEmpty(str)) {
      return str;
    }
    if (separator == null) {
      return EMPTY;
    }
    int pos = str.indexOf(separator);
    if (pos == -1) {
      return EMPTY;
    }
    return str.substring(pos + separator.length());
  }

  /**
   * <p>Gets the substring before the last occurrence of a separator.
   * The separator is not returned.</p>
   *
   * <p>A <code>null</code> string input will return <code>null</code>.
   * An empty ("") string input will return the empty string.
   * An empty or <code>null</code> separator will return the input string.</p>
   *
   * <pre>
   * StringUtils.substringBeforeLast(null, *)      = null
   * StringUtils.substringBeforeLast("", *)        = ""
   * StringUtils.substringBeforeLast("abcba", "b") = "abc"
   * StringUtils.substringBeforeLast("abc", "c")   = "ab"
   * StringUtils.substringBeforeLast("a", "a")     = ""
   * StringUtils.substringBeforeLast("a", "z")     = "a"
   * StringUtils.substringBeforeLast("a", null)    = "a"
   * StringUtils.substringBeforeLast("a", "")      = "a"
   * </pre>
   *
   * @param str  the String to get a substring from, may be null
   * @param separator  the String to search for, may be null
   * @return the substring before the last occurrence of the separator,
   *  <code>null</code> if null String input
   * @since 2.0
   */
  public static String substringBeforeLast(String str, String separator) {
    if (isEmpty(str) || isEmpty(separator)) {
      return str;
    }
    int pos = str.lastIndexOf(separator);
    if (pos == -1) {
      return str;
    }
    return str.substring(0, pos);
  }

  /**
   * <p>Gets the substring after the last occurrence of a separator.
   * The separator is not returned.</p>
   *
   * <p>A <code>null</code> string input will return <code>null</code>.
   * An empty ("") string input will return the empty string.
   * An empty or <code>null</code> separator will return the empty string if
   * the input string is not <code>null</code>.</p>
   *
   * <pre>
   * StringUtils.substringAfterLast(null, *)      = null
   * StringUtils.substringAfterLast("", *)        = ""
   * StringUtils.substringAfterLast(*, "")        = ""
   * StringUtils.substringAfterLast(*, null)      = ""
   * StringUtils.substringAfterLast("abc", "a")   = "bc"
   * StringUtils.substringAfterLast("abcba", "b") = "a"
   * StringUtils.substringAfterLast("abc", "c")   = ""
   * StringUtils.substringAfterLast("a", "a")     = ""
   * StringUtils.substringAfterLast("a", "z")     = ""
   * </pre>
   *
   * @param str  the String to get a substring from, may be null
   * @param separator  the String to search for, may be null
   * @return the substring after the last occurrence of the separator,
   *  <code>null</code> if null String input
   * @since 2.0
   */
  public static String substringAfterLast(String str, String separator) {
    if (isEmpty(str)) {
      return str;
    }
    if (isEmpty(separator)) {
      return EMPTY;
    }
    int pos = str.lastIndexOf(separator);
    if (pos == -1 || pos == (str.length() - separator.length())) {
      return EMPTY;
    }
    return str.substring(pos + separator.length());
  }

  /**
   * get the value from the argMap, throw exception if not there and required
   * @param argMap the map of arguments
   * @param argMapNotUsed map that tracks unused arguments
   * @param key argument key
   * @param required wheter or not the key is required to be present
   * @param defaultValue the value to use when the value looked up from key is blank
   * @return the value or null or exception
   */
  public static Integer argMapInteger(Map<String, String> argMap, Map<String, String> argMapNotUsed, 
      String key, boolean required, Integer defaultValue) {
    String argString = argMapString(argMap, argMapNotUsed, key, required);

    if (isBlank(argString) && required) {
      throw new RuntimeException("Argument '--" + key + "' is required, but not specified.  e.g. --" + key + "=5");
    }
    if (isBlank(argString)) {
      if (defaultValue != null) {
        return defaultValue;
      }
      return null;
    }
    return intValue(argString);
  }

  /**
   * null safe convert from java.util.Date to java.sql.Date
   * @param date the java Date to be converted
   * @return the sql date
   */
  public static java.sql.Date toSqlDate(Date date) {
    if (date == null) {
      return null;
    }
    return new java.sql.Date(date.getTime());
  }

  /**
   * <p>Find the index of the given object in the array.</p>
   *
   * <p>This method returns <code>-1</code> if <code>null</code> array input.</p>
   * 
   * @param array  the array to search through for the object, may be <code>null</code>
   * @param objectToFind  the object to find, may be <code>null</code>
   * @return the index of the object within the array, 
   *  <code>-1</code> if not found or <code>null</code> array input
   */
  public static int indexOf(Object[] array, Object objectToFind) {
    return indexOf(array, objectToFind, 0);
  }

  /**
   * <p>Checks if the object is in the given array.</p>
   *
   * <p>The method returns <code>false</code> if a <code>null</code> array is passed in.</p>
   * 
   * @param array  the array to search through
   * @param objectToFind  the object to find
   * @return <code>true</code> if the array contains the object
   */
  public static boolean contains(Object[] array, Object objectToFind) {
    return indexOf(array, objectToFind) != -1;
  }

  /**
   * <p>Find the index of the given object in the array starting at the given index.</p>
   *
   * <p>This method returns <code>-1</code> if <code>null</code> array input.</p>
   *
   * <p>A negative startIndex is treated as zero. A startIndex larger than the array
   * length will return <code>-1</code>.</p>
   * 
   * @param array  the array to search through for the object, may be <code>null</code>
   * @param objectToFind  the object to find, may be <code>null</code>
   * @param startIndex  the index to start searching at
   * @return the index of the object within the array starting at the index,
   *  <code>-1</code> if not found or <code>null</code> array input
   */
  public static int indexOf(Object[] array, Object objectToFind, int startIndex) {
    if (array == null) {
      return -1;
    }
    if (startIndex < 0) {
      startIndex = 0;
    }
    if (objectToFind == null) {
      for (int i = startIndex; i < array.length; i++) {
        if (array[i] == null) {
          return i;
        }
      }
    } else {
      for (int i = startIndex; i < array.length; i++) {
        if (objectToFind.equals(array[i])) {
          return i;
        }
      }
    }
    return -1;
  }

  /**
   * Note, this is web service format string
   */
  private static final String WS_DATE_FORMAT = "yyyy/MM/dd HH:mm:ss.SSS";

  /**
   * Note, this is web service format string
   */
  private static final String WS_DATE_FORMAT2 = "yyyy/MM/dd_HH:mm:ss.SSS";

  /**
   * convert a date to a string using the standard web service pattern
   * yyyy/MM/dd HH:mm:ss.SSS Note that HH is 0-23
   * 
   * @param date the date to convert
   * @return the string, or null if the date is null
   */
  public static String dateToString(Date date) {
    if (date == null) {
      return null;
    }
    SimpleDateFormat simpleDateFormat = new SimpleDateFormat(WS_DATE_FORMAT);
    return simpleDateFormat.format(date);
  }

  /**
   * convert a string to a date using the standard web service pattern Note
   * that HH is 0-23
   * 
   * @param dateString the string to parse into a date
   * @return the string, or null if the date was null
   */
  public static Date stringToDate(String dateString) {
    if (isBlank(dateString)) {
      return null;
    }
    SimpleDateFormat simpleDateFormat = new SimpleDateFormat(WS_DATE_FORMAT);
    try {
      return simpleDateFormat.parse(dateString);
    } catch (ParseException e) {
      SimpleDateFormat simpleDateFormat2 = new SimpleDateFormat(WS_DATE_FORMAT2);
      try {
        return simpleDateFormat2.parse(dateString);
      } catch (ParseException e2) {
        throw new RuntimeException("Cannot convert '" + dateString
            + "' to a date based on format: " + WS_DATE_FORMAT, e);
      }
    }
  }

  /**
   * match regex pattern yyyy-mm-dd or yyyy/mm/dd
   */
  private static Pattern datePattern_yyyy_mm_dd = Pattern.compile("^(\\d{4})[^\\d]+(\\d{1,2})[^\\d]+(\\d{1,2})$");
  
  /**
   * match regex pattern dd-mon-yyyy or dd/mon/yyyy
   */
  private static Pattern datePattern_dd_mon_yyyy = Pattern.compile("^(\\d{1,2})[^\\d]+([a-zA-Z]{3,15})[^\\d]+(\\d{4})$");
  
  /**
   * match regex pattern yyyy-mm-dd hh:mm:ss or yyyy/mm/dd hh:mm:ss
   */
  private static Pattern datePattern_yyyy_mm_dd_hhmmss = Pattern.compile("^(\\d{4})[^\\d]+(\\d{1,2})[^\\d]+(\\d{1,2})[^\\d]+(\\d{1,2})[^\\d]+(\\d{1,2})[^\\d]+(\\d{1,2})$");
  
  /**
   * match regex pattern dd-mon-yyyy hh:mm:ss or dd/mon/yyyy hh:mm:ss
   */
  private static Pattern datePattern_dd_mon_yyyy_hhmmss = Pattern.compile("^(\\d{1,2})[^\\d]+([a-zA-Z]{3,15})[^\\d]+(\\d{4})[^\\d]+(\\d{1,2})[^\\d]+(\\d{1,2})[^\\d]+(\\d{1,2})$");
  
  /**
   * match regex pattern yyyy-mm-dd hh:mm:ss.SSS or yyyy/mm/dd hh:mm:ss.SSS
   */
  private static Pattern datePattern_yyyy_mm_dd_hhmmss_SSS = Pattern.compile("^(\\d{4})[^\\d]+(\\d{1,2})[^\\d]+(\\d{1,2})[^\\d]+(\\d{1,2})[^\\d]+(\\d{1,2})[^\\d]+(\\d{1,2})[^\\d]+(\\d{1,3})$");
  
  /**
   * match regex pattern dd-mon-yyyy hh:mm:ss.SSS or dd/mon/yyyy hh:mm:ss.SSS
   */
  private static Pattern datePattern_dd_mon_yyyy_hhmmss_SSS = Pattern.compile("^(\\d{1,2})[^\\d]+([a-zA-Z]{3,15})[^\\d]+(\\d{4})[^\\d]+(\\d{1,2})[^\\d]+(\\d{1,2})[^\\d]+(\\d{1,2})[^\\d]+(\\d{1,3})$");
  
  /**
   * take as input:
   * yyyy/mm/dd
   * yyyy-mm-dd
   * dd-mon-yyyy
   * yyyy/mm/dd hh:mm:ss
   * dd-mon-yyyy hh:mm:ss
   * yyyy/mm/dd hh:mm:ss.SSS
   * dd-mon-yyyy hh:mm:ss.SSS
   * @param input the string to parse into a date
   * @return the date
   */
  public static Date stringToDate2(String input) {
    
    if (isBlank(input)) {
      return null;
    }
    input = input.trim();
    Matcher matcher = null;
    
    int month = 0;
    int day = 0;
    int year = 0;
    int hour = 0;
    int minute = 0;
    int second = 0;
    int milli = 0;
    
    boolean foundMatch = false;

    //yyyy/mm/dd
    if (!foundMatch) {
      matcher = datePattern_yyyy_mm_dd.matcher(input);
      if (matcher.matches()) {
        year = intValue(matcher.group(1));
        month =  intValue(matcher.group(2));
        day = intValue(matcher.group(3));
        foundMatch = true;
      }
    }
    
    //dd-mon-yyyy
    if (!foundMatch) {
      matcher = datePattern_dd_mon_yyyy.matcher(input);
      if (matcher.matches()) {
        day = intValue(matcher.group(1));
        month =  monthInt(matcher.group(2));
        year = intValue(matcher.group(3));
        foundMatch = true;
      }
    }
    
    //yyyy/mm/dd hh:mm:ss
    if (!foundMatch) {
      matcher = datePattern_yyyy_mm_dd_hhmmss.matcher(input);
      if (matcher.matches()) {
        year = intValue(matcher.group(1));
        month =  intValue(matcher.group(2));
        day = intValue(matcher.group(3));
        hour = intValue(matcher.group(4));
        minute = intValue(matcher.group(5));
        second = intValue(matcher.group(6));
        foundMatch = true;
      }      
    }
    
    //dd-mon-yyyy hh:mm:ss
    if (!foundMatch) {
      matcher = datePattern_dd_mon_yyyy_hhmmss.matcher(input);
      if (matcher.matches()) {
        day = intValue(matcher.group(1));
        month =  monthInt(matcher.group(2));
        year = intValue(matcher.group(3));
        hour = intValue(matcher.group(4));
        minute = intValue(matcher.group(5));
        second = intValue(matcher.group(6));
        foundMatch = true;
      }
    }
    
    //yyyy/mm/dd hh:mm:ss.SSS
    if (!foundMatch) {
      matcher = datePattern_yyyy_mm_dd_hhmmss_SSS.matcher(input);
      if (matcher.matches()) {
        year = intValue(matcher.group(1));
        month =  intValue(matcher.group(2));
        day = intValue(matcher.group(3));
        hour = intValue(matcher.group(4));
        minute = intValue(matcher.group(5));
        second = intValue(matcher.group(6));
        milli = intValue(matcher.group(7));
        foundMatch = true;
      }      
    }
    
    //dd-mon-yyyy hh:mm:ss.SSS
    if (!foundMatch) {
      matcher = datePattern_dd_mon_yyyy_hhmmss_SSS.matcher(input);
      if (matcher.matches()) {
        day = intValue(matcher.group(1));
        month =  monthInt(matcher.group(2));
        year = intValue(matcher.group(3));
        hour = intValue(matcher.group(4));
        minute = intValue(matcher.group(5));
        second = intValue(matcher.group(6));
        milli = intValue(matcher.group(7));
        foundMatch = true;
      }
    }
    
    Calendar calendar = Calendar.getInstance();
    calendar.set(Calendar.YEAR, year);
    calendar.set(Calendar.MONTH, month-1);
    calendar.set(Calendar.DAY_OF_MONTH, day);
    calendar.set(Calendar.HOUR_OF_DAY, hour);
    calendar.set(Calendar.MINUTE, minute);
    calendar.set(Calendar.SECOND, second);
    calendar.set(Calendar.MILLISECOND, milli);
    return calendar.getTime();
  }

  /**
   * convert a month string to an int (1 indexed).
   * e.g. if input is feb or Feb or february or February return 2
   * @param mon English month string such as "jan, feb, march, april, may, jun, june, ..."
   * @return the month number 1 - 12 for "january" - "december"
   */
  public static int monthInt(String mon) {
    
    if (!isBlank(mon)) {
      mon = mon.toLowerCase();
      
      if (equals(mon, "jan") || equals(mon, "january")) {
        return 1;
      }
      
      if (equals(mon, "feb") || equals(mon, "february")) {
        return 2;
      }
      
      if (equals(mon, "mar") || equals(mon, "march")) {
        return 3;
      }
      
      if (equals(mon, "apr") || equals(mon, "april")) {
        return 4;
      }
      
      if (equals(mon, "may")) {
        return 5;
      }
      
      if (equals(mon, "jun") || equals(mon, "june")) {
        return 6;
      }
      
      if (equals(mon, "jul") || equals(mon, "july")) {
        return 7;
      }
      
      if (equals(mon, "aug") || equals(mon, "august")) {
        return 8;
      }
      
      if (equals(mon, "sep") || equals(mon, "september")) {
        return 9;
      }
      
      if (equals(mon, "oct") || equals(mon, "october")) {
        return 10;
      }
      
      if (equals(mon, "nov") || equals(mon, "november")) {
        return 11;
      }
      
      if (equals(mon, "dec") || equals(mon, "december")) {
        return 12;
      }
      
    }
    
    throw new RuntimeException("Invalid month: " + mon);
  }

  /**
   * override map for properties in thread local to be used in a web server or the like, based on property file name
   * @param propertiesFileName properties file name
   * @return the override map
   */
  public static Map<String, String> propertiesThreadLocalOverrideMap(String propertiesFileName) {
    Map<String, Map<String, String>> overrideMap = propertiesThreadLocalOverrideMap.get();
    if (overrideMap == null) {
      overrideMap = new HashMap<String, Map<String, String>>();
      propertiesThreadLocalOverrideMap.set(overrideMap);
    }
    Map<String, String> propertiesOverrideMap = overrideMap.get(propertiesFileName);
    if (propertiesOverrideMap == null) {
      propertiesOverrideMap = new HashMap<String, String>();
      overrideMap.put(propertiesFileName, propertiesOverrideMap);
    }
    return propertiesOverrideMap;
  }

  
  /**
   * This will execute a command, and split spaces for args (might not be what
   * you want if you are using quotes)
   * 
   * @param command The command string to execute
   */
  public static void execCommand(String command) {
    String[] args = splitTrim(command, " ");
    execCommand(args);
  }

  /**
   * Gobble up a stream from a runtime
   * @author mchyzer
   * @param <V> the gobbler type
   */
  private static class StreamGobbler<V> implements Callable<V> {
    
    /** stream to read */
    InputStream inputStream;
    
    /** where to put the result */
    String resultString;

    /** type of the output for logging purposes */
    String type;
    
    /** command to log */
    String command;
    /**
     * construct
     * @param is
     * @param theType 
     * @param theCommand
     */
    StreamGobbler(InputStream is, String theType, String theCommand) {
      this.inputStream = is;
      this.type = theType;
      this.command = theCommand;
    }

    /**
     * get the string result
     * @return the result
     */
    public String getResultString() {
      return this.resultString;
    }

    // @Override
    public V call() throws Exception {
      try {
        
        StringWriter stringWriter = new StringWriter();
        copy(this.inputStream, stringWriter);
        this.resultString = stringWriter.toString();

      } catch (Exception e) {

        throw new RuntimeException(e);

      }
      return null;
    }
  }
  
  /**
   * <pre>This will execute a command (with args). In this method, 
   * if the exit code of the command is not zero, an exception will be thrown.
   * Example call: execCommand(new String[]{"/bin/bash", "-c", "cd /someFolder; runSomeScript.sh"}, true);
   * </pre>
   * @param arguments are the commands
   * @return the output text of the command.
   */
  public static CommandResult execCommand(String[] arguments) {
    return execCommand(arguments, true);
  }
  
  /**
   * threadpool
   */
  private static ExecutorService executorService = Executors.newCachedThreadPool(new DaemonThreadFactory());


  /**
   * 
   * @return executor service
   */
  public static ExecutorService retrieveExecutorService() {
    return executorService;
  }
  
  /**
   * <pre>This will execute a command (with args). Under normal operation, 
   * if the exit code of the command is not zero, an exception will be thrown.
   * If the parameter exceptionOnExitValueNeZero is set to true, the 
   * results of the call will be returned regardless of the exit status.
   * Example call: execCommand(new String[]{"/bin/bash", "-c", "cd /someFolder; runSomeScript.sh"}, true);
   * </pre>
   * @param arguments are the commands
   * @param exceptionOnExitValueNeZero if this is set to false, the 
   * results of the call will be returned regardless of the exit status
   * @return the output text of the command, and the error and return code if exceptionOnExitValueNeZero is false.
   */
  public static CommandResult execCommand(String[] arguments, boolean exceptionOnExitValueNeZero) {
    Process process = null;

    StringBuilder commandBuilder = new StringBuilder();
    for (int i = 0; i < arguments.length; i++) {
      commandBuilder.append(arguments[i]).append(" ");
    }
    String command = commandBuilder.toString();
    StreamGobbler<Object> outputGobbler = null;
    StreamGobbler<Object> errorGobbler = null;
    try {
      process = Runtime.getRuntime().exec(arguments);

      outputGobbler = new StreamGobbler<Object>(process.getInputStream(), ".out", command);
      errorGobbler = new StreamGobbler<Object>(process.getErrorStream(), ".err", command);

      Future<Object> futureOutput = retrieveExecutorService().submit(outputGobbler);
      Future<Object> futureError = retrieveExecutorService().submit(errorGobbler);
      
      try {
        process.waitFor();
      } finally {
        
        //finish running these threads
        try {
          futureOutput.get();
        } finally {
          //ignore if cant get
        }
        try {
          futureError.get();
        } finally {
          //ignore if cant get
        }
      }
    } catch (Exception e) {
      throw new RuntimeException("Error running command", e);
    } finally {
      try {
        process.destroy();
      } catch (Exception e) {
      }
    }
    
    //was not successful???
    if (process.exitValue() != 0 && exceptionOnExitValueNeZero) {
      String message = "Process exit status=" + process.exitValue() + ": out: " + 
        (outputGobbler == null ? null : outputGobbler.getResultString())
        + ", err: " + (errorGobbler == null ? null : errorGobbler.getResultString());
      throw new RuntimeException(message);
    }

    int exitValue = process.exitValue();
    return new CommandResult(outputGobbler.getResultString(), errorGobbler.getResultString(), exitValue);
  }

  
  /**
   * The results of executing a command.
   */
  public static class CommandResult{
    /**
     * If any error text was generated by the call, it will be set here.
     */
    private String errorText;
    
    /**
     * If any output text was generated by the call, it will be set here.
     */
    private String outputText;
    
    /**
     * If any exit code was generated by the call, it will be set here.
     */
    private int exitCode;
    
    
    /**
     * Create a container to hold the results of an execution.
     * @param _errorText the error text
     * @param _outputText the output text
     * @param _exitCode the exit code
     */
    public CommandResult(String _errorText, String _outputText, int _exitCode){
      this.errorText = _errorText;
      this.outputText = _outputText;
      this.exitCode = _exitCode;
    }


    
    /**
     * If any error text was generated by the call, it will be set here.
     * @return the errorText
     */
    public String getErrorText() {
      return this.errorText;
    }


    
    /**
     * If any output text was generated by the call, it will be set here.
     * @return the outputText
     */
    public String getOutputText() {
      return this.outputText;
    }


    
    /**
     * If any exit code was generated by the call, it will be set here.
     * @return the exitCode
     */
    public int getExitCode() {
      return this.exitCode;
    }
    
    
    
  }

  /**
   * thread factory with daemon threads so the JVM exits
   * @author mchyzer
   *
   */
  private static class DaemonThreadFactory implements ThreadFactory {
    private ThreadFactory threadFactory = Executors.defaultThreadFactory();
  
    @Override
    public Thread newThread(Runnable r) {
      Thread thread = threadFactory.newThread(r);
      thread.setDaemon(true);
      return thread;
    }
  
  }

  /**
   * serialize an object to a file (create parent dir if necessary)
   * @param object the serializable object
   * @param file the destination file
   */
  public static void serializeObjectToFile(Serializable object, File file) {

    //delete, make sure parents are there
    deleteCreateFile(file);

    FileOutputStream fos = null;
    ObjectOutputStream out = null;
    try {
      fos = new FileOutputStream(file);
      out = new ObjectOutputStream(fos);
      out.writeObject(object);
    } catch(IOException ex) {
      //we had a problem, don't leave the file partway created...
      closeQuietly(out);
      out = null;
      deleteFile(file);
      throw new RuntimeException("Error writing file: " + absolutePath(file)
          + ", " + className(object), ex);
    } finally {
      closeQuietly(out);
    }
    
  }

  /**
   * unserialize an object from a file if it exists
   * @param file the file containing the serialized object
   * @param nullIfException true if null should be returned instead of exception
   * @param deleteFileOnException true if file should be deleted on exception
   * @return the object or null
   */
  public static Serializable unserializeObjectFromFile(File file, boolean nullIfException,
      boolean deleteFileOnException) {
    
    if (!file.exists() || file.length() == 0) {
      return null;
    }
    
    FileInputStream fis = null;
    ObjectInputStream ois = null;
    try {
      fis = new FileInputStream(file);
      ois = new ObjectInputStream(fis);
      return (Serializable)ois.readObject();
    } catch(Exception ex) {
      String error = "Error writing file: " + absolutePath(file);
      if (!nullIfException) {
        throw new RuntimeException(error, ex);
      }
      //maybe clear the file if problem
      if (deleteFileOnException) {
        //close before deleting
        closeQuietly(ois);
        ois = null;
        deleteFile(file);
      }
      return null;
    } finally {
      closeQuietly(ois);
    }
    
  }
  
  /**
   * delete and create a new file.  If its a directory, delete, and create a new dir.
   * 
   * @param file
   *          is the file to delete and create
   */
  public static void deleteCreateFile(File file) {

    deleteFile(file);

    createParentDirectories(file);

    try {
      if (!file.createNewFile()) {
        throw new IOException("createNewFile returned false: ");
      }
    } catch (IOException ioe) {
      throw new RuntimeException("Couldnt create new file: " + file.toString(), ioe);
    }

  }

  /**
   * Delete a file, throw exception if cannot
   * @param file the file or directory to delete
   */
  public static void deleteFile(File file) {
    //delete and create
    if (file != null && file.exists()) {

      if (file.isDirectory()) {
        deleteRecursiveDirectory(file.getAbsolutePath());
      } else if (!file.delete()) {
        throw new RuntimeException("Couldnt delete file: " + file.toString());
      }
    }
  }

  /**
   * copy a file to a new file
   * @param fromFile source file
   * @param toFile target file
   */
  public static void copy(File fromFile, File toFile) {
    if (toFile.exists()) {
      deleteFile(toFile);
    }
    FileInputStream fromFileStream = null;
    FileOutputStream toFileStream = null;
    try {
      fromFileStream = new FileInputStream(fromFile);
      toFileStream = new FileOutputStream(toFile);
      copy(fromFileStream, toFileStream);
    } catch (Exception e) {
      throw new RuntimeException("Problem copying file: " + fromFile.getAbsolutePath() 
          + " to file: " + toFile.getAbsolutePath());
    }
    // Adding finally block to ensure streams are closed
    finally {
      try{
        fromFileStream.close();
        toFileStream.close();
      }
      catch (IOException e) {
        throw new RuntimeException("Problem closing FileStream while copying file: " + fromFile.getAbsolutePath()
            + " to file: " + toFile.getAbsolutePath());
      }
    }
  }

  /**
   * rename a file to another file and throw runtime exception if not ok
   * @param fromFile source file
   * @param toFile target file
   */
  public static void renameTo(File fromFile, File toFile) {

    if (!fromFile.renameTo(toFile)) {
      throw new RuntimeException("Cannot rename file: '" + fromFile.getAbsolutePath() 
          + "', to file: '" + toFile.getAbsolutePath() + "'");
    }

  }

  /**
   * clear out all files recursively in a directory, including the directory
   * itself
   * @param dirName the directory name to delete
   * 
   * @throws RuntimeException
   *           when something goes wrong
   */
  public static void deleteRecursiveDirectory(String dirName) {
    //delete all files in the directory
    File dir = new File(dirName);

    //if it doesnt exist then we are done
    if (!dir.exists()) {
      return;
    }

    //see if its a directory
    if (!dir.isDirectory()) {
      throw new RuntimeException("The directory: " + dirName + " is not a directory");
    }

    //get the files into a vector
    File[] allFiles = dir.listFiles();

    //loop through the array
    for (int i = 0; i < allFiles.length; i++) {
      if (-1 < allFiles[i].getName().indexOf("..")) {
        continue; //dont go to the parent directory
      }

      if (allFiles[i].isFile()) {
        //delete the file
        if (!allFiles[i].delete()) {
          throw new RuntimeException("Could not delete file: " + allFiles[i].getPath());
        }
      } else {
        //its a directory
        deleteRecursiveDirectory(allFiles[i].getPath());
      }
    }

    //delete the directory itself
    if (!dir.delete()) {
      throw new RuntimeException("Could not delete directory: " + dir.getPath());
    }
  }

  /**
   * absolute path null safe
   * @param file the absolute path of the given file, or null
   * @return absolute path null safe
   */
  public static String absolutePath(File file) {
    return file == null ? null : file.getAbsolutePath();
  }


  /**
   * pattern to get the file path or resource location for a file
   */
  private static Pattern fileLocationPattern = Pattern.compile("^(file|classpath)\\s*:(.*)$");
  
  /**
   * file or classpath location
   * @param typeAndLocation the string describing the resource. Begins with "file:" or "classpath:".
   * @param logHint used as prefix for RuntimeException messages
   * @return the inputstream
   */
  public static InputStream fileOrClasspathInputstream(String typeAndLocation, String logHint) {
    Matcher matcher = fileLocationPattern.matcher(typeAndLocation);
    if (!matcher.matches()) {
      throw new RuntimeException(logHint + " must start with file: or classpath:");
    }
    String typeString = matcher.group(1);
    String location = trim(matcher.group(2));
    
    if (equals(typeString, "file")) {
      File file = new File(location);
      if (!file.exists() || !file.isFile()) {
        throw new RuntimeException(logHint + " File does not exist: " + file.getAbsolutePath());
      }
      try {
        return new FileInputStream(file);
      } catch (Exception e) {
        throw new RuntimeException(logHint + " Problem with file: " + file.getAbsolutePath());
      }
    } else if (equals(typeString, "classpath")) {
      if (!location.startsWith("/")) {
        location = "/" + location;
      }
      try {
        return ConfigPropertiesCascadeCommonUtils.class.getResourceAsStream(location);
      } catch (Exception e) {
        throw new RuntimeException(logHint + " Problem with classpath location: " + location);
      }
    } else {
      throw new RuntimeException(logHint + " Not expecting type string: " + typeString);
    }
    
  }
  


}
