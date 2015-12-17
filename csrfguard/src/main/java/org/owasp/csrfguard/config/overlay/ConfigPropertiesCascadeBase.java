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

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.StringReader;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Pattern;

import org.owasp.csrfguard.log.ILogger;
import org.owasp.csrfguard.log.LogLevel;
import org.owasp.csrfguard.util.CsrfGuardUtils;


/**
 * Base class for a cascaded config.  Extend this class to have a config
 * based on a certain file. 
 * 
 * @author mchyzer
 *
 */
public abstract class ConfigPropertiesCascadeBase {

	/**
	 * help subclasses manipulate properties.  note, this is only for subclasses...
	 * @return properties
	 */
	protected Properties internalProperties() {
		return this.properties;
	}

	/** if a key ends with this, then it is an EL property */
	private static final String EL_CONFIG_SUFFIX = ".elConfig";

	/**
	 * this is used to tell engine where the default and example config is...
	 */
	private static Map<Class<? extends ConfigPropertiesCascadeBase>, ConfigPropertiesCascadeBase> configSingletonFromClass = null;

	/**
	 * retrieve a config from the config file or from cache
	 * @param <T> class which is the return type of config class
	 * @param configClass  The configuration object
	 * @return the config object never null
	 */
	@SuppressWarnings("unchecked")
	protected static <T extends ConfigPropertiesCascadeBase> T retrieveConfig(Class<T> configClass) {

		if (configSingletonFromClass == null) {
			configSingletonFromClass = 
					new HashMap<Class<? extends ConfigPropertiesCascadeBase>, ConfigPropertiesCascadeBase>();
		}

		ConfigPropertiesCascadeBase configPropertiesCascadeBase = configSingletonFromClass.get(configClass);
		if (configPropertiesCascadeBase == null) {
			configPropertiesCascadeBase = ConfigPropertiesCascadeUtils.newInstance(configClass, true);
			configSingletonFromClass.put(configClass, configPropertiesCascadeBase);

		}
		//from the singleton, get the real config class
		return (T)configPropertiesCascadeBase.retrieveFromConfigFileOrCache();
	}


	/**
	 * if it's ok to put the config file in the same directory as a jar,
	 * then return a class in the jar here
	 * @return the class or null if not available
	 */
	protected Class<?> getClassInSiblingJar() {
		return null;
	}

	/**
	 * config key of the time in seconds to check config.  -1 means dont check again
	 * @return config key
	 */
	protected abstract String getSecondsToCheckConfigKey();

	/**
	 * if there are things that are calculated, clear them out (e.g. if an override is set)
	 */
	public abstract void clearCachedCalculatedValues();

	/** override map for properties in thread local to be used in a web server or the like */
	private static ThreadLocal<Map<Class<? extends ConfigPropertiesCascadeBase>, Map<String, String>>> propertiesThreadLocalOverrideMap 
	= null;

	/**
	 * override map for properties in thread local to be used in a web server or the like, based on property class
	 * this is static since the properties class can get reloaded, but these shouldn't
	 * @return the override map
	 */
	public Map<String, String> propertiesThreadLocalOverrideMap() {
		if (propertiesThreadLocalOverrideMap == null) {
			propertiesThreadLocalOverrideMap = new ThreadLocal<Map<Class<? extends ConfigPropertiesCascadeBase>, Map<String, String>>>();
		}

		Map<Class<? extends ConfigPropertiesCascadeBase>, Map<String, String>> overrideMap = propertiesThreadLocalOverrideMap.get();
		if (overrideMap == null) {
			overrideMap = new HashMap<Class<? extends ConfigPropertiesCascadeBase>, Map<String, String>>();
			propertiesThreadLocalOverrideMap.set(overrideMap);
		}
		Map<String, String> propertiesOverrideMapLocal = overrideMap.get(this.getClass());
		if (propertiesOverrideMapLocal == null) {
			propertiesOverrideMapLocal = new HashMap<String, String>();
			overrideMap.put(this.getClass(), propertiesOverrideMapLocal);
		}
		return propertiesOverrideMapLocal;
	}

	/** override map for properties, for testing, put properties in here, based on config class
	 * this is static since the properties class can get reloaded, but these shouldn't
	 */
	private static Map<Class<? extends ConfigPropertiesCascadeBase>, Map<String, String>> propertiesOverrideMap 
	= null;

	/**
	 * @return the set of property names
	 * @see java.util.Hashtable#keySet()
	 */
	@SuppressWarnings("unchecked")
	public Set<String> propertyNames() {    

		Set<String> result = new LinkedHashSet<String>();
		result.addAll((Set<String>)(Object)this.propertiesHelper(false).keySet());
		return result;
	}

	/**
	 * override map for properties for testing
	 * @return the override map
	 */
	public Map<String, String> propertiesOverrideMap() {
		if (propertiesOverrideMap == null) {
			propertiesOverrideMap 
			= new LinkedHashMap<Class<? extends ConfigPropertiesCascadeBase>, Map<String, String>>();
		}
		Map<String, String> overrideMap = propertiesOverrideMap.get(this.getClass());
		if (overrideMap == null) {
			overrideMap = new LinkedHashMap<String, String>();
			propertiesOverrideMap.put(this.getClass(), overrideMap);
		}
		return overrideMap;
	}

	/**
	 * get the properties object for this config file
	 * @return the properties
	 */
	public Properties properties() {
		return propertiesHelper(true);
	}

	/**
	 * get the properties object for this config file
	 * @param setValues if we should set the values for the properties.  
	 * if not, the values might not be correct, but this will be more performant
	 * depending on how many EL properties there are
	 * @return the properties
	 */
	@SuppressWarnings("unchecked")
	protected Properties propertiesHelper(boolean setValues) {
		Properties tempResult = new Properties();

		tempResult.putAll(this.properties);

		Map<String, String> localPropertiesOverrideMap = propertiesOverrideMap();

		for (String key: localPropertiesOverrideMap.keySet()) {
			tempResult.put(key, ConfigPropertiesCascadeUtils.defaultString(localPropertiesOverrideMap.get(key)));
		}

		localPropertiesOverrideMap = propertiesThreadLocalOverrideMap();

		for (String key: localPropertiesOverrideMap.keySet()) {
			tempResult.put(key, ConfigPropertiesCascadeUtils.defaultString(localPropertiesOverrideMap.get(key)));
		}

		Properties result = new Properties();

		for (String key : (Set<String>)(Object)tempResult.keySet()) {

			String value = setValues ? this.properties.getProperty(key) : "";

			//lets look for EL
			if (key.endsWith(EL_CONFIG_SUFFIX)) {

				if (setValues) {
					//process the EL
					value = ConfigPropertiesCascadeUtils.substituteExpressionLanguage(value, null, true, true, true, false);
				}

				//change the key name
				key = key.substring(0, key.length() - EL_CONFIG_SUFFIX.length());
			}
			//cant be null, or hashtable exception
			result.put(key, ConfigPropertiesCascadeUtils.defaultString(value));
		}

		return result;

	}

	/** properties from the properties file(s) */
	private Properties properties = new Properties();

	/**
	 * get the property value as a string
	 * @param key The property name
	 * @return the property value, or null if not found
	 */
	public String propertyValueStringRequired(String key) {
		return propertyValueString(key, null, true).getTheValue();
	}

	/**
	 * get the property value as a string
	 * @param key The property name
	 * @param defaultValue The value used when such property value is found (in place of null)
	 * @return the property value
	 */
	public String propertyValueString(String key, String defaultValue) {
		return propertyValueString(key, defaultValue, false).getTheValue();
	}

	/**
	 * get the property value as a string or null if not there
	 * @param key The property name
	 * @return the property value
	 */
	public String propertyValueString(String key) {
		return propertyValueString(key, null, false).getTheValue();
	}

	/**
	 * result of a property value
	 */
	static class PropertyValueResult {


		/**
		 * 
		 * @param theValue1 property value
		 * @param hasKey1 whether or not the key exists
		 */
		public PropertyValueResult(String theValue1, boolean hasKey1) {
			super();
			this.theValue = theValue1;
			this.hasKey = hasKey1;
		}


		/** value from lookup */
		private String theValue;

		/** if there is a key in the properties file */
		private boolean hasKey;


		/**
		 * value from lookup
		 * @return the theValue
		 */
		public String getTheValue() {
			return this.theValue;
		}


		/**
		 * value from lookup
		 * @param theValue1 the theValue to set
		 */
		public void setTheValue(String theValue1) {
			this.theValue = theValue1;
		}


		/**
		 * if there is a key in the properties file
		 * @return the hasKey
		 */
		public boolean isHasKey() {
			return this.hasKey;
		}


		/**
		 * if there is a key in the properties file
		 * @param hasKey1 the hasKey to set
		 */
		public void setHasKey(boolean hasKey1) {
			this.hasKey = hasKey1;
		}

	}

	/**
	 * get the property value as a string
	 * @param key property key
	 * @param defaultValue value to use when key is not found
	 * @param required When true, throw an exception if the key does not exist
	 * @return the property value
	 */
	protected PropertyValueResult propertyValueString(String key, String defaultValue, boolean required) {
		if (key.endsWith(EL_CONFIG_SUFFIX)) {
			throw new RuntimeException("Why does key end in suffix??? " + EL_CONFIG_SUFFIX + ", " + key);
		}
		return propertyValueStringHelper(key, defaultValue, required);
	}

	/**
	 * get the property value as a string
	 * @param key property key
	 * @param defaultValue value to use when key is not found
	 * @param required When true, throw an exception if the key does not exist
	 * @return the property value
	 */
	protected PropertyValueResult propertyValueStringHelper(String key, String defaultValue, boolean required) {

		//lets look for EL
		if (!key.endsWith(EL_CONFIG_SUFFIX)) {

			PropertyValueResult elPropertyValueResult = propertyValueStringHelper(key + EL_CONFIG_SUFFIX, null, false);

			if (elPropertyValueResult.isHasKey()) {

				//process the EL
				String result = ConfigPropertiesCascadeUtils.substituteExpressionLanguage(elPropertyValueResult.getTheValue(), null, true, true, true, false);
				PropertyValueResult propertyValueResult = new PropertyValueResult(result, true);
				return propertyValueResult;
			}

		}

		//first check threadlocal map
		boolean hasKey = false;
		Map<String, String> overrideMap = propertiesThreadLocalOverrideMap();

		hasKey = overrideMap == null ? false : overrideMap.containsKey(key);
		String value = hasKey ? overrideMap.get(key) : null;
		if (!hasKey) {

			overrideMap = propertiesOverrideMap();

			hasKey = overrideMap == null ? null : overrideMap.containsKey(key);
			value = hasKey ? overrideMap.get(key) : null;
		}
		if (!hasKey) {
			hasKey = this.properties.containsKey(key);
			value = hasKey ? this.properties.getProperty(key) : null;
		}
		if (!required && !hasKey) {
			return new PropertyValueResult(defaultValue, false);
		}
		if (required && !hasKey) {
			String error = "Cant find property: " + key + " in properties file: " + this.getMainConfigClasspath() + ", it is required";

			throw new RuntimeException(error);
		}
		value = ConfigPropertiesCascadeUtils.trim(value);
		value = substituteCommonVars(value);

		if (!required && ConfigPropertiesCascadeUtils.isBlank(value)) {
			return new PropertyValueResult(null, true);
		}

		//do the validation if this is required
		if (required && ConfigPropertiesCascadeUtils.isBlank(value)) {
			String error = "Property " + key + " in properties file: " + this.getMainConfigClasspath() + ", has a blank value, it is required";

			throw new RuntimeException(error);
		}

		return new PropertyValueResult(value, true);
	}

	/**
	 * substitute common vars like $space$ and $newline$
	 * @param string input string
	 * @return new string with some dollar-delimited tokens replaced
	 */
	protected static String substituteCommonVars(String string) {
		if (string != null && string.indexOf('$') < 0 ) {
			//might have $space$
			string = ConfigPropertiesCascadeUtils.replace(string, "$space$", " ");

			//note, at some point we could be OS specific
			string = ConfigPropertiesCascadeUtils.replace(string, "$newline$", "\n");
		}
		return string;
	}

	/**
	 * when this config object was created
	 */
	private long createdTime = System.currentTimeMillis();

	/**
	 * when this config object was created
	 * @return the createdTime
	 */
	long getCreatedTime() {
		return this.createdTime;
	}

	/**
	 * when this config object was created or last checked for changes
	 */
	private long lastCheckedTime = System.currentTimeMillis();

	/**
	 * when this config object was created or last checked for changes
	 * @return created time or last checked
	 */
	long getLastCheckedTime() {
		return this.lastCheckedTime;
	}

	/**
	 * when we build the config object, get the time to check config in seconds
	 */
	private Integer timeToCheckConfigSeconds = null;

	/**
	 * when we build the config object, get the time to check config in seconds
	 * @return the time to check config foe changes (in seconds)
	 */
	protected Integer getTimeToCheckConfigSeconds() {
		return this.timeToCheckConfigSeconds;
	}

	/**
	 * config file cache
	 */
	private static Map<Class<? extends ConfigPropertiesCascadeBase>, ConfigPropertiesCascadeBase> configFileCache = null;

	/**
	 * config file type
	 */
	protected static enum ConfigFileType {

		/**
		 * get a config file from the filesystem
		 */
		FILE {

			@Override
			public InputStream inputStream(String configFileTypeConfig,
					ConfigPropertiesCascadeBase configPropertiesCascadeBase) {
				File file = new File(configFileTypeConfig);
				if (!file.exists() || !file.isFile()) {
					throw new RuntimeException("Cant find config file from filesystem path: " + configFileTypeConfig);
				}
				try {
					return new FileInputStream(file);
				} catch (Exception e) {
					throw new RuntimeException("Problem reading config file from filesystem path: " + file.getAbsolutePath(), e);
				}
			}
		},

		/**
		 * get a config file from the classpath
		 */
		CLASSPATH {

			/**
			 * 
			 */
			@Override
			public InputStream inputStream(String configFileTypeConfig,
					ConfigPropertiesCascadeBase configPropertiesCascadeBase) {
				URL url = ConfigPropertiesCascadeUtils.computeUrl(configFileTypeConfig, true);
				Exception exception = null;
				if (url != null) {
					try {
						return url.openStream();
					} catch (Exception e) {
						exception = e;
					}
				}

				//if we didnt get there yet, lets look for a companion jar
				Class<?> classInJar = configPropertiesCascadeBase.getClassInSiblingJar();
				if (classInJar != null) {
					File jarFile = classInJar == null ? null : ConfigPropertiesCascadeUtils.jarFile(classInJar);
					File parentDir = jarFile == null ? null : jarFile.getParentFile();
					String fileName = parentDir == null ? null 
							: (ConfigPropertiesCascadeUtils.stripLastSlashIfExists(ConfigPropertiesCascadeUtils.fileCanonicalPath(parentDir)) + File.separator + configFileTypeConfig);
					File configFile = fileName == null ? null 
							: new File(fileName);

					//looks like we have a match
					if (configFile != null && configFile.exists() && configFile.isFile()) {
						try {
							return new FileInputStream(configFile);
						} catch (Exception e) {
							logError("Cant read config file: " + configFile.getAbsolutePath(), e);
						}
					}
				}
				//see if it is next to the jar
				throw new RuntimeException("Cant find config file from classpath: " + configFileTypeConfig, exception);
			}
		};

		/**
		 * get the inputstream to read the config 
		 * @param configFileTypeConfig The reference to the config file, used either as pathname for a File or a URL
		 * @param configPropertiesCascadeBase add the config object in case
		 * @return the input stream to get this config
		 */
		public abstract InputStream inputStream(String configFileTypeConfig, ConfigPropertiesCascadeBase configPropertiesCascadeBase);

		/**
		 * do a case-insensitive matching
		 * 
		 * @param string the config file type
		 * @return the enum or null or exception if not found
		 */
		public static ConfigFileType valueOfIgnoreCase(String string) {
			return ConfigPropertiesCascadeUtils.enumValueOfIgnoreCase(ConfigFileType.class,string, false );
		}

	}

	/**
	 * 
	 */
	protected static class ConfigFile {

		/**
		 * keep the original config string for logging purposes, e.g. file:/a/b/c.properties
		 */
		private String originalConfig;


		/**
		 * keep the original config string for logging purposes, e.g. file:/a/b/c.properties
		 * @return the originalConfig
		 */
		public String getOriginalConfig() {
			return this.originalConfig;
		}

		/**
		 * the contents when the config file was read
		 */
		private String contents = null;

		/**
		 * the contents when the config file was read
		 * @return the contents
		 */
		public String getContents() {
			return this.contents;
		}

		/**
		 * @param contents1 the contents to set
		 */
		public void setContents(String contents1) {
			this.contents = contents1;
		}

		/**
		 * get the contents from the config file
		 * @param configPropertiesCascadeBase the config properties cascade base
		 * @return the contents
		 */
		public String retrieveContents(ConfigPropertiesCascadeBase configPropertiesCascadeBase) {
			InputStream inputStream = null;
			try {
				inputStream = this.configFileType.inputStream(this.configFileTypeConfig, configPropertiesCascadeBase);
				return ConfigPropertiesCascadeUtils.toString(inputStream, "UTF-8");
			} catch (Exception e) {
				throw new RuntimeException("Problem reading config: '" + this.originalConfig + "'", e);
			} finally {
				CsrfGuardUtils.closeQuietly(inputStream);
			}
		}

		/**
		 * 
		 * @param configFileFullConfig The config file location reference such as file:/some/path/config.properties
		 */
		public ConfigFile(String configFileFullConfig) {

			this.originalConfig = configFileFullConfig;

			int colonIndex = configFileFullConfig.indexOf(':');

			if (colonIndex == -1) {
				throw new RuntimeException("Config file spec needs the type of config and a colon, e.g. file:/some/path/config.properties  '" + configFileFullConfig + "'");
			}

			//lets get the type
			String configFileTypeString = ConfigPropertiesCascadeUtils.trim(ConfigPropertiesCascadeUtils.prefixOrSuffix(configFileFullConfig, ":", true));

			if (ConfigPropertiesCascadeUtils.isBlank(configFileTypeString)) {
				throw new RuntimeException("Config file spec needs the type of config and a colon, e.g. file:/some/path/config.properties  '" + configFileFullConfig + "'");
			}

			try {
				this.configFileType = ConfigFileType.valueOfIgnoreCase(configFileTypeString);
			} catch (Exception e) {
				throw new RuntimeException("Config file spec needs the type of config and a colon, e.g. file:/some/path/config.properties  '" + configFileFullConfig + "', " + e.getMessage(), e);
			}

			this.configFileTypeConfig = ConfigPropertiesCascadeUtils.trim(ConfigPropertiesCascadeUtils.prefixOrSuffix(configFileFullConfig, ":", false));

		}

		/**
		 * the type of config file (file path, classpath, etc)
		 */
		private ConfigFileType configFileType;

		/**
		 * the config part which says which file or classpath etc
		 */
		private String configFileTypeConfig;


		/**
		 * the type of config file (file path, classpath, etc)
		 * @return the configFileType
		 */
		public ConfigFileType getConfigFileType() {
			return this.configFileType;
		}


		/**
		 * the config part which says which file or classpath etc
		 * @return the configFileTypeConfig
		 */
		public String getConfigFileTypeConfig() {
			return this.configFileTypeConfig;
		}



	}

	/**
	 * config files from least specific to more specific
	 */
	private List<ConfigFile> configFiles = null;

	/**
	 * get the config object from config files
	 * @return the config object
	 */
	protected ConfigPropertiesCascadeBase retrieveFromConfigFiles() {

		//lets get the config hierarchy...
		//properties from override first
		Properties mainConfigFile = propertiesFromResourceName(this.getMainConfigClasspath(), false);

		String secondsToCheckConfigString = null;

		String overrideFullConfig = null;

		if (mainConfigFile != null) {
			overrideFullConfig = mainConfigFile.getProperty(this.getHierarchyConfigKey());
			secondsToCheckConfigString = mainConfigFile.getProperty(this.getSecondsToCheckConfigKey());
		}

		//if couldnt find it from the override, get from example
		if (ConfigPropertiesCascadeUtils.isBlank(overrideFullConfig) || ConfigPropertiesCascadeUtils.isBlank(secondsToCheckConfigString)) {

			Properties mainExampleConfigFile = propertiesFromResourceName(this.getMainExampleConfigClasspath(), false);

			if (mainExampleConfigFile != null) {

				if (ConfigPropertiesCascadeUtils.isBlank(overrideFullConfig)) {
					overrideFullConfig = mainExampleConfigFile.getProperty(this.getHierarchyConfigKey());
				}
				if (ConfigPropertiesCascadeUtils.isBlank(secondsToCheckConfigString)) {
					secondsToCheckConfigString = mainExampleConfigFile.getProperty(this.getSecondsToCheckConfigKey());
				}

			}

		}

		//if hasnt found yet, there is a problem
		if (ConfigPropertiesCascadeUtils.isBlank(overrideFullConfig)) {
			throw new RuntimeException("Cant find the hierarchy config key: " + this.getHierarchyConfigKey() 
					+ " in config files: " + this.getMainConfigClasspath()
					+ " or " + this.getMainExampleConfigClasspath());
		}

		//if hasnt found yet, there is a problem
		if (ConfigPropertiesCascadeUtils.isBlank(secondsToCheckConfigString)) {
			throw new RuntimeException("Cant find the seconds to check config key: " + this.getSecondsToCheckConfigKey() 
					+ " in config files: " + this.getMainConfigClasspath()
					+ " or " + this.getMainExampleConfigClasspath());
		}

		//make a new return object based on this class
		ConfigPropertiesCascadeBase result = ConfigPropertiesCascadeUtils.newInstance(this.getClass(), true);

		try {
			result.timeToCheckConfigSeconds = ConfigPropertiesCascadeUtils.intValue(secondsToCheckConfigString);
		} catch (Exception e) {
			throw new RuntimeException("Invalid integer seconds to check config config value: " + secondsToCheckConfigString
					+ ", key: " + this.getSecondsToCheckConfigKey() 
					+ " in config files: " + this.getMainConfigClasspath()
					+ " or " + this.getMainExampleConfigClasspath());

		}

		//ok, we have the config file list...
		//lets get this into a comma separated list
		List<String> overrideConfigStringList = ConfigPropertiesCascadeUtils.splitTrimToList(overrideFullConfig, ",");

		result.configFiles = new ArrayList<ConfigFile>();

		for (String overrideConfigString : overrideConfigStringList) {

			ConfigFile configFile = new ConfigFile(overrideConfigString);
			result.configFiles.add(configFile);

			//lets append the properties
			//InputStream inputStream = configFile.getConfigFileType().inputStream(configFile.getConfigFileTypeConfig(), this);
			try {
				
				//get the string and store it first (to see if it changes later)
				String configFileContents = configFile.retrieveContents(this);
				configFile.setContents(configFileContents);
				result.properties.load(new StringReader(configFileContents));
				
			} catch (Exception e) {
				throw new RuntimeException("Problem loading properties: " + overrideConfigString, e);
			}
		}

		return result;

	}

	/**
	 * get the logger instance
	 * @return the ilogger
	 */
	private static ILogger iLogger() {
		//endless loop
		//CsrfGuard csrfGuard = CsrfGuard.getInstance();
		//ILogger iLogger = csrfGuard == null ? null : csrfGuard.getLogger();
		//return iLogger;
		return null;
		
	}

	/**
	 * make sure LOG is there, after things are initialized
	 * @param logMessage Message to log
	 * @param t Exception to log, or null
	 */
	protected static void logInfo(String logMessage, Exception t) {
		ILogger iLogger = iLogger();
		if (iLogger != null) {
			if (!ConfigPropertiesCascadeUtils.isBlank(logMessage)) {
				iLogger.log(LogLevel.Info, logMessage);
			}
			if (t != null) {
				iLogger.log(LogLevel.Info, t);
			}
		}
	}

	/**
	 * make sure LOG is there, after things are initialized
	 * @param logMessage Message to log
	 * @param t Exception to log, or null
	 */
	protected static void logError(String logMessage, Exception t) {
		ILogger iLogger = iLogger();
		if (iLogger != null) {
			if (!ConfigPropertiesCascadeUtils.isBlank(logMessage)) {
				iLogger.log(LogLevel.Info, logMessage);
			}
			if (t != null) {
				iLogger.log(LogLevel.Info, t);
			}
		} else {
			System.err.println("ERROR: " + logMessage);
			t.printStackTrace();
		}
	}

	/**
	 * see if there is one in cache, if so, use it, if not, get from config files
	 * @return the config from file or cache
	 */
	protected ConfigPropertiesCascadeBase retrieveFromConfigFileOrCache() {

		Map<String, Object> debugMap = new LinkedHashMap<String, Object>();

		try {

			if (configFileCache == null) {
				if (true) {
					debugMap.put("configFileCache", null);
				}

				configFileCache = 
						new HashMap<Class<? extends ConfigPropertiesCascadeBase>, ConfigPropertiesCascadeBase>();
			}

			ConfigPropertiesCascadeBase configObject = configFileCache.get(this.getClass());

			if (configObject == null) {

				if (true) {
					debugMap.put("mainConfigClasspath", this.getMainConfigClasspath());
				}

				configObject = retrieveFromConfigFiles();
				configFileCache.put(this.getClass(), configObject);

			} else {

				//see if that much time has passed
				if (configObject.needToCheckIfFilesNeedReloading()) {

					if (true) {
						debugMap.put("needToCheckIfFilesNeedReloading", true);
					}
					synchronized (configObject) {

						configObject = configFileCache.get(this.getClass());

						//check again in case another thread did it
						if (configObject.needToCheckIfFilesNeedReloading()) {

							if (true) {
								debugMap.put("needToCheckIfFilesNeedReloading2", true);
							}
							if (configObject.filesNeedReloadingBasedOnContents()) {
								if (true) {
									debugMap.put("filesNeedReloadingBasedOnContents", true);
								}
								configObject = retrieveFromConfigFiles();
								configFileCache.put(this.getClass(), configObject);
							}
						}
					}
				}
			}
			if (true) {
				debugMap.put("configObjectPropertyCount", configObject == null ? null 
						: (configObject.properties() == null ? "propertiesNull" : configObject.properties().size()));
			}

			return configObject;
		} finally {
			ILogger iLogger = iLogger();
			if (iLogger != null) {
				iLogger.log(LogLevel.Debug, ConfigPropertiesCascadeUtils.mapToString(debugMap));
			}
		}
	}

	/**
	 * 
	 * @return true if need to reload this config, false if not
	 */
	protected boolean needToCheckIfFilesNeedReloading() {

		//get the time that this was created
		long lastCheckedTimeLocal = this.getLastCheckedTime();

		//get the timeToCheckSeconds if different
		int timeToCheckSeconds = this.getTimeToCheckConfigSeconds();

		//never reload.  0 means reload all the time?
		if (timeToCheckSeconds < 0) {
			return false;
		}

		//see if that much time has passed
		if (System.currentTimeMillis() - lastCheckedTimeLocal > timeToCheckSeconds * 1000) {
			return true;
		}
		return false;

	}

	/**
	 * 
	 * @return true if need to reload this config, false if not
	 */
	protected boolean filesNeedReloadingBasedOnContents() {
		try {
			//lets look at all the files and see if they have changed...
			for (ConfigFile configFile : this.configFiles) {
				if (!ConfigPropertiesCascadeUtils.equals(configFile.getContents(), configFile.retrieveContents(this))) {
					return true;
				}
			}
		} catch (Exception e) {
			//lets log and return the old one
			logError("Error checking for changes in configs (will use previous version): " + this.getMainConfigClasspath(), e);
		} finally {
			//reset the time so we dont have to check again for a while
			this.lastCheckedTime = System.currentTimeMillis();
		}
		return false;
	}



	/**
	 * get the main config classpath, e.g. csrf guard properties
	 * @return the classpath of the main config file
	 */
	protected abstract String getMainConfigClasspath();

	/**
	 * config key of the hierarchy value
	 * @return the classpath of the main config file
	 */
	protected abstract String getHierarchyConfigKey();

	/**
	 * get the example config classpath, e.g. csrf guard base properties
	 * @return the classpath of the example config file
	 */
	protected abstract String getMainExampleConfigClasspath();

	/**
	 * get a boolean and validate from csrf guard properties
	 * @param key property key
	 * @param defaultValue valud to use when key is missing
	 * @return true when the property value represents an affirmative string such as {true, t, yes, y}
	 */
	public boolean propertyValueBoolean(String key, boolean defaultValue) {
		return propertyValueBoolean(key, defaultValue, false);
	}

	/**
	 * if the key is there, whether or not the value is blank
	 * @param key property key
	 * @return true or false
	 */
	public boolean containsKey(String key) {

		return propertyValueString(key, null, false).isHasKey();

	}

	/**
	 * get a boolean and validate from csrf guard properties or null if not there
	 * @param key property key
	 * @return the boolean or null
	 */
	public Boolean propertyValueBoolean(String key) {
		return propertyValueBoolean(key, null, false);
	}


	/**
	 * get a boolean pop and validate from the config file
	 * @param key property key
	 * @param defaultValue Used when no property value is found for the given key, when the 'required' option is not set
	 * @param required Whether or not a value is required to be present
	 * @return true when property value is string is one of {true, t, yes, y} and false when one of {false, f, no, n}
	 */
	protected Boolean propertyValueBoolean(String key, Boolean defaultValue, boolean required) {
		String value = propertyValueString(key, null, false).getTheValue();
		if (ConfigPropertiesCascadeUtils.isBlank(value) && !required) {
			return defaultValue;
		}
		if (ConfigPropertiesCascadeUtils.isBlank(value) && required) {
			throw new RuntimeException("Cant find boolean property " + key + " in properties file: " + this.getMainConfigClasspath() + ", it is required, expecting true or false");
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
		if ("yes".equalsIgnoreCase(value)) {
			return true;
		}
		if ("no".equalsIgnoreCase(value)) {
			return false;
		}
		if ("y".equalsIgnoreCase(value)) {
			return true;
		}
		if ("n".equalsIgnoreCase(value)) {
			return false;
		}
		throw new RuntimeException("Invalid boolean value: '" + value + "' for property: " + key 
				+ " in properties file: " + this.getMainConfigClasspath() + ", expecting true or false");

	}

	/**
	 * get an int and validate from the config file
	 * @param key property key
	 * @param defaultValue Used when no property value is found for the given key, when the 'required' option is not set
	 * @param required Whether or not a value is required to be present
	 * @return the property value
	 */
	protected Integer propertyValueInt(String key, Integer defaultValue, boolean required) {
		String value = propertyValueString(key, null, false).getTheValue();
		if (ConfigPropertiesCascadeUtils.isBlank(value) && !required) {
			return defaultValue;
		}
		if (ConfigPropertiesCascadeUtils.isBlank(value) && required) {
			throw new RuntimeException("Cant find integer property " + key + " in config file: " + this.getMainConfigClasspath() + ", it is required");
		}
		try {
			return ConfigPropertiesCascadeUtils.intValue(value);
		} catch (Exception e) {

		}
		throw new RuntimeException("Invalid integer value: '" + value + "' for property: " 
				+ key + " in config file: " + this.getMainConfigClasspath() + " in properties file");

	}

	/**
	 * get a boolean and validate from csrf guard properties
	 * @param key property key
	 * @return the boolean property value 
	 */
	public boolean propertyValueBooleanRequired(String key) {

		return propertyValueBoolean(key, false, true);

	}

	/**
	 * get a boolean and validate from csrf guard properties
	 * @param key property key
	 * @return the integer property value 
	 */
	public int propertyValueIntRequired(String key) {

		return propertyValueInt(key, -1, true);

	}

	/**
	 * get a boolean and validate from csrf guard properties
	 * @param key property key
	 * @param defaultValue Used when key not found
	 * @return the property value
	 */
	public int propertyValueInt(String key, int defaultValue ) {

		return propertyValueInt(key, defaultValue, false);

	}

	/**
	 * get a boolean and validate from csrf guard properties
	 * @param key property key
	 * @return the int or null if there
	 */
	public Integer propertyValueInt(String key ) {

		return propertyValueInt(key, null, false);

	}

	/**
	 * read properties from a resource, don't modify the properties returned since they are cached
	 * @param resourceName Name of properties resource
	 * @param exceptionIfNotExist When true, throw an exception if an URL for the resource name cannot be constructued
	 * @return the properties or null if not exist
	 */
	protected static Properties propertiesFromResourceName(String resourceName, 
			boolean exceptionIfNotExist) {

		Properties properties = new Properties();

		URL url = null;

		try {

			url = ConfigPropertiesCascadeUtils.computeUrl(resourceName, true);

		} catch (Exception e) {

			//I guess this ok
			logInfo("Problem loading config file: " + resourceName, e); 

		}

		if (url == null && exceptionIfNotExist) {
			throw new RuntimeException("Problem loading config file: " + resourceName);
		}

		if (url == null) {
			return null;
		}

		InputStream inputStream = null;
		try {
			inputStream = url.openStream();
			properties.load(inputStream);

		} catch (Exception e) {

			//why exception at this point?  not good
			throw new RuntimeException("Problem loading config file: " + resourceName, e);

		}
		return properties;
	}

	/**
	 * make sure a value exists in properties
	 * @param key property key
	 * @return true if property exists with non-blank value, false otherwise
	 */
	public boolean assertPropertyValueRequired(String key) {
		String value = propertyValueString(key);
		if (!ConfigPropertiesCascadeUtils.isBlank(value)) {
			return true;
		}
		String error = "Cant find property " + key + " in resource: " + this.getMainConfigClasspath() + ", it is required";
		System.err.println("CSRF guard error: " + error);
		ILogger iLogger = iLogger();
		if (iLogger != null) {
			iLogger.log(LogLevel.Error, error);
		}
		return false;
	}

	/**
	 * make sure a value is boolean in properties
	 * @param key property key
	 * @param required whether or not the key is required to be present
	 * @return true if ok, false if not
	 */
	public boolean assertPropertyValueBoolean(String key, boolean required) {

		if (required && !assertPropertyValueRequired(key)) {
			return false;
		}

		String value = propertyValueString(key);
		//maybe ok not there
		if (!required && ConfigPropertiesCascadeUtils.isBlank(value)) {
			return true;
		}
		try {
			ConfigPropertiesCascadeUtils.booleanValue(value);
			return true;
		} catch (Exception e) {

		}
		String error = "Expecting true or false property " + key + " in resource: " + this.getMainConfigClasspath() + ", but is '" + value + "'";
		System.err.println("csrf guard error: " + error);
		ILogger iLogger = iLogger();
		if (iLogger != null) {
			iLogger.log(LogLevel.Error, error);
		}
		return false;
	}

	/**
	 * make sure a property is a class of a certain type
	 * @param key property key
	 * @param classType Desired class type
	 * @param required Whether or not key must be present and have non-blank value
	 * @return true if ok
	 */
	public boolean assertPropertyValueClass(
			String key, Class<?> classType, boolean required) {

		if (required && !assertPropertyValueRequired(key)) {
			return false;
		}
		String value = propertyValueString(key);

		//maybe ok not there
		if (!required && ConfigPropertiesCascadeUtils.isBlank(value)) {
			return true;
		}

		String extraError = "";
		try {


			Class<?> theClass = ConfigPropertiesCascadeUtils.forName(value);
			if (classType.isAssignableFrom(theClass)) {
				return true;
			}
			extraError = " does not derive from class: " + classType.getSimpleName();

		} catch (Exception e) {
			extraError = ", " + ConfigPropertiesCascadeUtils.getFullStackTrace(e);
		}
		String error = "Cant process property " + key + " in resource: " + this.getMainConfigClasspath() + ", the current" +
				" value is '" + value + "', which should be of type: " 
				+ classType.getName() + extraError;
		System.err.println("csrf guard error: " + error);
		ILogger iLogger = iLogger();
		if (iLogger != null) {
			iLogger.log(LogLevel.Error, error);
		}
		return false;
	}

	/**
	 * find all keys/values with a certain pattern in a properties file.
	 * return the keys.  if none, will return the empty set, not null set
	 * @param pattern expression matched against property names
	 * @return the matching keys.  if none, will return the empty set, not null set
	 */
	public Map<String, String> propertiesMap(Pattern pattern) {
		Map<String, String> result = new LinkedHashMap<String, String>();
		for (String key: propertyNames()) {
			if (pattern.matcher(key).matches()) {
				result.put(key, propertyValueString(key));
			}
		}

		return result;
	}


}
