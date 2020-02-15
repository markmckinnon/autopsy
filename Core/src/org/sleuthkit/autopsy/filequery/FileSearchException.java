/*
 * Autopsy Forensic Browser
 *
 * Copyright 2019 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
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
 */
package org.sleuthkit.autopsy.filequery;

/**
 * Exception type used for FileSearch
 */
public class FileSearchException extends Exception {
    private static final long serialVersionUID = 1L;
    
    /**
     * Create exception from a string
     * 
     * @param message 
     */
    public FileSearchException(String message) {
        super(message);
    }
    
    /**
     * Create exception for a string and cause
     * 
     * @param message
     * @param cause 
     */
    public FileSearchException(String message, Throwable cause) {
        super(message, cause);
    }
}
