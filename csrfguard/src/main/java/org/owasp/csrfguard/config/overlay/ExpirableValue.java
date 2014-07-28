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


/**
 * This holds the actual value of the map, and the time it was inserted, and
 * the time that it should last in the cache
 * @version $Id: ExpirableValue.java,v 1.1 2008-11-27 14:25:50 mchyzer Exp $
 * @author mchyzer
 * @param <T> is the type of the underlying content
 */
public class ExpirableValue<T> implements Serializable {

  /** this is the time it was placed in the cache */
  private long timePlacedInCache = System.currentTimeMillis();
  
  /** the time to live is by default 1 day */
  private long timeToLiveInCacheMillis = ExpirableCache.MAX_TIME_TO_LIVE_MILLIS;
  
  /** underlying content */
  private T content = null;
  
  /**
   * Makes an expirable value with max 1 day time to live
   * @param theContent content to store
   * @param theTimeToLiveInCacheMillis number of millis the items should stay in cache.
   * this cannot be longer than 1 day
   */
  ExpirableValue(T theContent, long theTimeToLiveInCacheMillis) {
    super();
    //cant be longer then the max
    if (theTimeToLiveInCacheMillis > 0 && 
        theTimeToLiveInCacheMillis <= ExpirableCache.MAX_TIME_TO_LIVE_MILLIS) {
      this.timeToLiveInCacheMillis = theTimeToLiveInCacheMillis;
    }
    this.content = theContent;
  }

  /**
   * dont call this on expired content!  check first.  get the content
   * @return Returns the content.
   */
  T getContent() {
    if (this.expiredLongTime()) {
      throw new RuntimeException("This content is expired!");
    }
    return this.content;
  }

  
  /**
   * see if the content is expired
   * @return true if expired
   */
  boolean expired() {
    return System.currentTimeMillis() - this.timePlacedInCache > this.timeToLiveInCacheMillis;
  }
  
  /**
   * see if the content is expired 3 seconds ago, to eliminate race conditions
   * @return true if expired
   */
  boolean expiredLongTime() {
    return (System.currentTimeMillis() - 3000) - this.timePlacedInCache > this.timeToLiveInCacheMillis;
  }
}
