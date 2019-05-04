/* 
 * Copyright (c) 2019 chaoticgd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// You are sat at your Commodore 64, eating pasta by candle light. The goal
// is in sight: You are going to hack into the NSA mainframe, but to do so you
// must overwrite the signatures of every function in a function pointer table.
// Doing this by hand would be unthunkable, so you write a script to assist in
// your illicit activities. Determined, you fire up Eclipse and start working.
// Weeks later, maybe even months, or years in the future, you emerge from your
// cave to declare to the world that your work is complete. You had done it. You
// had mastered the art of computer hacking and demonstrated your skills in the
// most elite way possible. How would society repay you? You quickly find that
// no one seems to care. Was it that you had taken too long? The year is 5354.
// The Snowden leaks were long ago, and have long since been removed from public
// debate. You decide to write a Medium article reflecting on your experience.
// It quickly receives five claps and reaches the ninth page of Hacker News.
// The end.
//@author chaoticgd
//@category Functions
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.framework.cmd.Command;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;

public class BatchOverwriteFunctionSignatures extends GhidraScript {

	public void run() throws Exception {
		
		String newSignatureStr = askString("Enter New Function Signature", "");
		FunctionSignatureParser parser = new FunctionSignatureParser(currentProgram, null);
		FunctionDefinitionDataType sig = parser.parse(null, newSignatureStr);
		
		CompoundCmd batchOverwriteSig = new CompoundCmd("Batch Overwrite Function Signatures");
		
		AddressIterator iter = currentSelection.getAddresses(true);
		while(iter.hasNext()) {
			Address ptr = iter.next();
			Address funcAddr = ptr.getNewAddress(currentProgram.getMemory().getInt(ptr));
			Function func = currentProgram.getFunctionManager().getFunctionAt(funcAddr);
			if(func == null) {
				continue;
			}
			
			var dtm = currentProgram.getDataTypeManager();
			var namedSig = (FunctionDefinitionDataType) sig.copy(dtm);
			namedSig.setName(func.getName());
			
			Command cmd = new ApplyFunctionSignatureCmd(func.getEntryPoint(), namedSig, SourceType.ANALYSIS, true, true);
			batchOverwriteSig.add(cmd);
		}
		
		if(!batchOverwriteSig.applyTo(currentProgram)) {
			throw new Exception("Cannot apply command!");
		}
	}

}
