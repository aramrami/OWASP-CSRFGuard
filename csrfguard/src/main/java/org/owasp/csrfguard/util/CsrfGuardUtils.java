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
package org.owasp.csrfguard.util;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.Reader;
import java.io.StringWriter;
import java.io.Writer;
import java.lang.annotation.Annotation;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletConfig;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

/**
 *
 */
public class CsrfGuardUtils {

	private CsrfGuardUtils() {}

	/**
	 * for a url, get the protocol and domain, e.g. for url https://a.b/path, will return https://a.b
	 * @param url a string representing a URL
	 * @param includeProtocol
	 * @return the path with or without the protocol
	 */
	public static String httpProtocolAndDomain(String url, boolean includeProtocol) {
		if (includeProtocol) {
			return httpProtocolAndDomain(url);
		}

		return httpProtocolAndDomain(url.replaceFirst("^(http[s]?)://",""));
	}

	/**
	 * for a url, get the protocol and domain, e.g. for url https://a.b/path, will return https://a.b
	 * @param url a string representing a URL
	 * @return the protocol and path
	 */
	public static String httpProtocolAndDomain(String url) {
		int firstSlashAfterProtocol = url.indexOf('/', 8);
		if (firstSlashAfterProtocol < 0) {
			//must not have a path
			return url;
		}

		return url.substring(0, firstSlashAfterProtocol);
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
		try {
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
		} catch (RuntimeException re) {
			String message = "Problem calling method " + methodName
					+ " on " + (theClass == null ? null : theClass.getName());
			if (injectInException(re, message)) {
				throw re;
			}
			throw new RuntimeException(message, re);
		}
	}


	/**
	 * <pre>Returns the class object.</pre>
	 * @param origClassName is fully qualified
	 * @return the class
	 */
	public static Class forName(String origClassName) {

		try {
			return Class.forName(origClassName);
		} catch (Throwable t) {
			throw new RuntimeException("Problem loading class: " + origClassName, t);
		}

	}

	public static String getInitParameter(ServletConfig servletConfig, String name, 
			String configFileDefaultParamValue, String defaultValue) {
		String value = servletConfig.getInitParameter(name);

		if (value == null || "".equals(value.trim())) {
			value = configFileDefaultParamValue;
		}

		if (value == null || "".equals(value.trim())) {
			value = defaultValue;
		}

		return value;
	}

	public static String readResourceFileContent(String resourceName, boolean errorIfNotFound) {
		InputStream is = null;

		try {
			is = CsrfGuardUtils.class.getClassLoader().getResourceAsStream(resourceName);
			if(is == null) {
				if (errorIfNotFound) {
					throw new IllegalStateException("Could not find resource " + resourceName);
				}
				//not error if not found?  then null
				return null;
			}
			return readInputStreamContent(is);
		} finally {
			Streams.close(is);
		}
	}
	public static String readFileContent(String fileName) {
		InputStream is = null;

		try {
			is = new FileInputStream(fileName);
			return readInputStreamContent(is);
		} catch (IOException ioe) {
			throw new RuntimeException(ioe);
		} finally {	
			Streams.close(is);
		}
	}
	public static String readInputStreamContent(InputStream is) {
		StringBuilder sb = new StringBuilder();

		try {
			int i;

			while ((i = is.read()) > 0) {
				sb.append((char) i);
			}
		} catch (IOException ioe) {
			throw new RuntimeException(ioe);
		}

		return sb.toString();
	}

	/**
	 * If we can, inject this into the exception, else return false
	 * @param t the throwable
	 * @param message the method to inject
	 * @return true if success, false if not
	 */
	public static boolean injectInException(Throwable t, String message) {

		//this is the field for sun java 1.5
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
	 * See if the input is null or if string, if it is empty or blank (whitespace)
	 * @param input the object being tested for blank
	 * @return true if blank
	 */
	public static boolean isBlank(Object input) {
		if (null == input) {
			return true;
		}
		return (input instanceof String && isBlank((String)input));
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
	 * Null safe array length or map
	 *
	 * @param arrayOrCollection an arrar, Collection, or Map
	 * @return the length of the array (0 for null, 1 for non-array non-collection objects)
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
	 * null safe classname method, gets the unenhanced name
	 *
	 * @param object the object for which to get the class name
	 * @return the classname
	 */
	public static String className(Object object) {
		return object == null ? null : object.getClass()
				.getName();
	}

	/**
	 * null safe classname method, max out at 20
	 *
	 * @param object the collection
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
	 * null safe iterator getter if the type if collection
	 *
	 * @param collection the collection for which to return an iterator
	 * @return the iterator
	 */
	public static Iterator iterator(Object collection) {
		if (collection == null) {
			return null;
		}
		// array list doesn't need an iterator
		if (collection instanceof Collection
				&& !(collection instanceof ArrayList)) {
			return ((Collection) collection).iterator();
		}
		return null;
	}

	/**
	 * If array, get the element based on index, if Collection, get it based on
	 * iterator.
	 *
	 * @param arrayOrCollection an array, ArraList, or Collection
	 * @param iterator the iterator for the collection
	 * @param index the index into the array
	 * @return the object at the specified index or iterator.next()
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
	 * get a field object for a class, potentially in superclasses
	 *
	 * @param theClass the class containing the desired field
	 * @param fieldName the name of the field
	 * @param callOnSupers
	 *            true if superclasses should be looked in for the field
	 * @param throwExceptionIfNotFound
	 *            will throw runtime exception if not found
	 * @return the field object or null if not found (or exception if param is
	 *         set)
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
	 * If necessary, convert an object to another type.  if type is Object.class, just return the input.
	 * Do not convert null to an empty primitive
	 * @param <T> is template type
	 * @param value the value object
	 * @param theClass the class type
	 * @return the object of that instance converted into something else
	 */
	public static <T> T typeCast(Object value, Class<T> theClass) {
		//default behavior is not to convert null to empty primitive
		return typeCast(value, theClass, false, false);
	}

	/**
	 * If necessary, convert an object to another type.  if type is Object.class, just return the input
	 * @param <T> is the type to return
	 * @param value the value object
	 * @param theClass the class type
	 * @param convertNullToDefaultPrimitive if the value is null, and theClass is primitive, should we
	 * convert the null to a primitive default value
	 * @param useNewInstanceHooks if theClass is not recognized, then honor the string "null", "newInstance",
	 * or get a constructor with one param, and call it
	 * @return the object of that instance converted into something else
	 */
	@SuppressWarnings("unchecked")
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
		if (theClass.equals(String.class)) {
			resultValue = value == null ? null : value.toString();
		} else if (theClass.equals(value.getClass())) {
			resultValue = value;
		} else {
			throw new RuntimeException("Cannot convert from type: " + value.getClass() + " to type: " + theClass);
		}

		return (T)resultValue;
	}

	/**
	 * Construct a class
	 * @param <T> template type
	 * @param theClass the class on which to invoke newInstance()
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
	 * @param input A (possibly null) Reader to close
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
	 * close a resultSet null safe and dont throw exception
	 * @param resultSet the result set to close
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

	/**
	 * close a statement null safe and dont throw exception
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
	 * close a writer quietly
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
	 * close a writer quietly
	 * @param writer the xml stream writer to close
	 */
	public static void closeQuietly(XMLStreamWriter writer) {
		if (writer != null) {
			try {
				writer.close();
			} catch (XMLStreamException e) {
				//swallow, its ok
			}
		}
	}

	/**
	 * print out various types of objects
	 *
	 * @param object the object for which to generate a string representation
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
	 * @param object the object for which to generate a string representation
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
	 * print out various types of objects
	 *
	 * @param object the object for which to generate a string representation
	 * @param maxChars is where it should stop when figuring out object.  note, result might be longer than max...
	 * need to abbreviate when back
	 * @param result is where to append to
	 */
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
	              toStringForLog(Array.get(object, i), maxChars)).append("\n");
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
	              toStringForLog(collectionObject, maxChars)).append("\n");
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
	public static Throwable[] getThrowables(Throwable throwable) {
	    List list = new ArrayList();
	    while (throwable != null) {
	        list.add(throwable);
	        throwable = getCause(throwable);
	    }
	    return (Throwable[]) list.toArray(new Throwable[list.size()]);
	}

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
	 * <p>Introspects the <code>Throwable</code> to obtain the cause.</p>
	 *
	 * <p>The method searches for methods with specific names that return a
	 * <code>Throwable</code> object. This will pick up most wrapping exceptions,
	 * including those from JDK 1.4, and Apache Commons Lang&#8482; 
	 * <a href="https://commons.apache.org/proper/commons-lang/javadocs/api-2.6/org/apache/commons/lang/exception/NestableException.html">
	 * NestableException</a>.
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
	 * An empty immutable <code>Object</code> array.
	 */
	public static final Object[] EMPTY_OBJECT_ARRAY = new Object[0];

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

    @SuppressWarnings("unchecked")
    public static <T, E> T getMapKeyByValue(Map<T, E> map, E value) {
        for (Map.Entry<T, E> entry : map.entrySet()) {
            if (entry.getValue().equals(value)) {
                return entry.getKey();
            }
        }
        return null;
    }

}
