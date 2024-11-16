/*
 * Sly Technologies Free License
 * 
 * Copyright 2024 Sly Technologies Inc.
 *
 * Licensed under the Sly Technologies Free License (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * 
 * http://www.slytechs.com/free-license-text
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package com.slytechs.jnet.jnetruntime.jnpl.vm.api;

import java.nio.ByteBuffer;

/**
 * Context for extension instruction execution.
 * 
 * @author Mark Bednarczyk
 * 
 */
public interface ExecutionContext {

	/**
	 * Gets the packet data buffer.
	 * 
	 * @return Packet buffer
	 */
	ByteBuffer getPacketBuffer();

	/**
	 * Gets the value of a register.
	 * 
	 * @param register Register number
	 * @return Register value
	 */
	long getRegister(int register);

	/**
	 * Sets a register value.
	 * 
	 * @param register Register number
	 * @param value    Value to set
	 */
	void setRegister(int register, long value);

	/**
	 * Sets the program result.
	 * 
	 * @param result Execution result
	 */
	void setResult(long result);

	/**
	 * Gets protocol information.
	 * 
	 * @param layer Protocol layer
	 * @return Protocol info or null if not available
	 */
	ProtocolInfo getProtocolInfo(int layer);

	/**
	 * Sets an error condition.
	 * 
	 * @param errorType  Error type
	 * @param errorValue Error value
	 */
	void setError(int errorType, long errorValue);
}