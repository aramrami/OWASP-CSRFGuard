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

import java.io.Serializable;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;


/**
 * <p>
 * This is like a map, but the setters also take an expire time which 
 * will mean the items in the cache will be automatically deleted.  
 * Also, every so often (e.g. 2 minutes) all items are checked for expiration.
 * If no timetolive is set, it will default to 1 day.  The max time to live is
 * one day.
 * </p>
 *
 * <p>This is synchronized so that all access is safe.</p>
 *
 * <p>
 * <b>Note:</b> evictions are checked for periodically, but only when the map 
 * is accessed (and even then only every few minutes).
 * You can check for evictions externally, or clear the map if you are done with it.
 * </p>
 *
 * @version $Id: ExpirableCache.java,v 1.1 2008-11-27 14:25:50 mchyzer Exp $
 * @author mchyzer
 * @param <K> key type
 * @param <V> value type
 */
@SuppressWarnings("serial")
public class ExpirableCache<K,V> implements Serializable {

  /** max time to live in millis */
  static long MAX_TIME_TO_LIVE_MILLIS = 1000 * 60 * 60 * 24; //1 day

  /** time to live for content (when not specified this is one day, and max one day) */
  long defaultTimeToLiveInMillis = MAX_TIME_TO_LIVE_MILLIS;
  
  /** time between looking for evictions in millis, default to two minutes */
  static long TIME_BETWEEN_EVICTIONS_MILLIS = 2 * 60 * 1000;
  
  /** last time the cache was checked for evictions */
  long lastEvictionCheck = System.currentTimeMillis();
  
  /** cache map */
  private Map<K,ExpirableValue<V>> cache = new HashMap<K,ExpirableValue<V>>();
  
  /** number of elements inserted into the cache */
  private int cacheInserts = 0;
  
  /** numebr of times an element was retrieved from cache successfully */
  private int cacheHits = 0;
  
  /** number of evictions from cache when thigns expire */
  private int cacheEvictions = 0;
  
  /** global number of elements inserted into the cache, no need to synchronize */
  private static int globalCacheInserts = 0;
  
  /** numebr of times an element was retrieved from cache successfully, no need to synchronize */
  private static int globalCacheHits = 0;
  
  /** number of evictions from cache when thigns expire, no need to synchronize */
  private static int globalCacheEvictions = 0;
  
  /** when was the last clear of all */
  private static long lastClearStatic = -1;
  
  /** when was the last clear of this instance */
  private long lastClear = System.currentTimeMillis();
  
  /**
   * 
   */
  public ExpirableCache() {
    super();
  }
  
  /**
   * delete the cache
   *
   */
  public synchronized void clear() {
    this.cache.clear();
  }

  /**
   * @param defaultTimeToLiveInMinutes time in minutes is the default cache time to live for content
   */
  public ExpirableCache(int defaultTimeToLiveInMinutes) {
    super();
    if (defaultTimeToLiveInMinutes <= 0) {
      throw new RuntimeException("Time to live in minutes must be greater than 0");
    }
    //make sure this is less than the max
    long newTimeToLiveMillis = (long)defaultTimeToLiveInMinutes * 60 * 1000;
    if (newTimeToLiveMillis < MAX_TIME_TO_LIVE_MILLIS) {
      this.defaultTimeToLiveInMillis = newTimeToLiveMillis;
    }
  }

  /**
   * unit of time for expirable cache
   * @author mchyzer
   *
   */
  public static enum ExpirableCacheUnit {
    /** minutes */
    MINUTE {

      /** 
       * @see ExpirableCacheUnit#defaultTimeToLiveMillis(int)
       */
      @Override
      public long defaultTimeToLiveMillis(int input) {
        return (long)input * 60 * 1000;
      }
    },
    
    /** seconds */
    SECOND {

      /** 
       * @see ExpirableCacheUnit#defaultTimeToLiveMillis(int)
       */
      @Override
      public long defaultTimeToLiveMillis(int input) {
        return (long)input * 1000;
      }
    };
    
    /** 
     * default time to live based on units
     * @param input A number of units (seconds or minutes) before cache expires to be converted into milliseconds
     * @return the millis
     */
    public abstract long defaultTimeToLiveMillis(int input);
    
  }
  
  /**
   * @param defaultTimeToLive time in whatever unit is the default cache time to live for content
   * @param expirableCacheUnit is minutes or seconds
   */
  public ExpirableCache(ExpirableCacheUnit expirableCacheUnit, int defaultTimeToLive) {
    super();
    if (defaultTimeToLive <= 0) {
      throw new RuntimeException("Time to live in minutes must be greater than 0");
    }
    //make sure this is less than the max
    long newTimeToLiveMillis = expirableCacheUnit.defaultTimeToLiveMillis(defaultTimeToLive);
    if (newTimeToLiveMillis < MAX_TIME_TO_LIVE_MILLIS) {
      this.defaultTimeToLiveInMillis = newTimeToLiveMillis;
    }
  }

  /**
   * expose the length of cache
   * @return length of cache
   */
  public long getDefaultTimeToLiveInMillis() {
    return this.defaultTimeToLiveInMillis;
  }

  /**
   * put a value into the cache, accept the default time to live for this cache
   * @param key key type
   * @param value value type
   */
  public synchronized void put(K key, V value) {
    this.putHelper(key, value, this.defaultTimeToLiveInMillis);
  }
  
  /**
   * put a value into the cache, accept the default time to live for this cache
   * @param key key type
   * @param value value type
   * @param timeToLiveInMinutes time to live for this item in minutes.
   * If -1 then use the default
   */
  public synchronized void put(K key, V value, int timeToLiveInMinutes) {
    
    //see if the default
    if (timeToLiveInMinutes == -1) {
      this.put(key,value);
      return;
    }
    
    if (timeToLiveInMinutes <= 0) {
      throw new RuntimeException("Time to live in minutes must be greater than 0");
    }
    this.putHelper(key, value, (long)timeToLiveInMinutes * 60 * 1000);
  }

  /**
   * put a value into the cache, accept the default time to live for this cache
   * @param key key type
   * @param value value type
   * @param proposedTimeToLiveInMillis millis time to live
   */
  synchronized void putHelper(K key, V value, long proposedTimeToLiveInMillis) {
    
    this.checkForEvictions(true);
    long newTimeToLiveInMillis = this.defaultTimeToLiveInMillis;
    //dont use what was inputted if it is out of range
    if (proposedTimeToLiveInMillis > 0 
        && proposedTimeToLiveInMillis <= ExpirableCache.MAX_TIME_TO_LIVE_MILLIS) {
      newTimeToLiveInMillis = proposedTimeToLiveInMillis;
    }
    ExpirableValue<V> expirableValue = new ExpirableValue<V>(value, newTimeToLiveInMillis);
    this.cache.put(key, expirableValue);
    this.cacheInserts++;
    globalCacheInserts++;
  }
  
  /**
   * clear out all caches everywhere (session, request, context, etc)
   */
  public static void clearAll() {
    lastClearStatic = System.currentTimeMillis();
  }
  
  /**
   * check and remove elements that are stale
   * @param onlyCheckIfNeeded true if only check every so often (e.g. every two minutes)
   */
  public synchronized void checkForEvictions(boolean onlyCheckIfNeeded) {
    long now = System.currentTimeMillis();
    
    //first see if there is an all clear
    if (lastClearStatic > this.lastClear) {
      this.clear();
      this.lastClear = now;
      return;
    }
    
    if (onlyCheckIfNeeded) {
      if (now - this.lastEvictionCheck < ExpirableCache.TIME_BETWEEN_EVICTIONS_MILLIS) {
        return;
      }
    }
    
    //go through all elements, evict if stale
    Set<K> keySet = this.cache.keySet();
    Iterator<K> keyIterator = keySet.iterator();
    while (keyIterator.hasNext()) {
      K key = keyIterator.next();
      ExpirableValue<V> expirableValue = this.cache.get(key);
      if (expirableValue.expired()) {
        keyIterator.remove();
        this.cacheEvictions++;
        ExpirableCache.globalCacheEvictions++;
      }
    }
    
    //set that we just checked
    this.lastEvictionCheck = now;
  }
  
  /**
   * get a value or null if not there or expired
   * this will check for eviction, and evict if evictable
   * @param key key type
   * @return the value or null if not there or evicted
   */
  public synchronized V get(K key) {

    this.checkForEvictions(true);
    return this.getHelper(key);
  }
  /**
   * get a value or null if not there or expired
   * this will check for eviction, and evict if evictable
   * @param key key for the cached value
   * @return the value or null if not there or evicted
   */
  private synchronized V getHelper(K key) {

    ExpirableValue<V> value = this.cache.get(key);
    if (value == null) {
      //shouldnt have a key with no value, probably doesnt exist, but just in case
      this.cache.remove(key);
      return null;
    }
    if (value.expired()) {
      this.cacheEvictions++;
      ExpirableCache.globalCacheEvictions++;
      this.cache.remove(key);
      return null;
    }
    V content = value.getContent();
    this.cacheHits++;
    ExpirableCache.globalCacheHits++;
    return content;
  }
  
  /**
   * number of elements in map (and check for 
   * @param evictEvictables true if we should evict values that are stale 
   * (even if recently checked)
   * @return the number of elements
   */
  public synchronized int size(boolean evictEvictables) {
    if (evictEvictables) {
      this.checkForEvictions(false);
    }
    return this.cache.size();
  }

  
  /**
   * number of items inserted into the cache
   * @return Returns the cacheInserts.
   */
  public int getCacheInserts() {
    return this.cacheInserts;
  }

  
  /**
   * number of items evicted from cache
   * @return Returns the cacheEvictions.
   */
  public int getCacheEvictions() {
    return this.cacheEvictions;
  }

  
  /**
   * number of items successfully retrieved from cache
   * @return Returns the cacheHits.
   */
  public int getCacheHits() {
    return this.cacheHits;
  }

  /**
   * string representation of cache
   * @see java.lang.Object#toString()
   */
  @Override
public String toString() {
    this.checkForEvictions(true);
    return this.getClass().getSimpleName() + ": size: " + this.size(false)
      + ", cacheHits: " + this.getCacheHits() + ", cacheInserts: " 
      + this.getCacheInserts() + ", cacheEvictions: " + this.cacheEvictions;
  }
  
  /**
   * string representation of cache
   * @return the string value
   */
  public static String staticToString() {
    return "ExpirableCacheGlobal, cacheHits: " + globalCacheHits + ", cacheInserts: " 
      + globalCacheInserts + ", cacheEvictions: " + globalCacheEvictions;
  }
}
