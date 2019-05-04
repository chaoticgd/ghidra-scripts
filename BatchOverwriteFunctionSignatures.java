/*
 * Copyright (c) 2019 chaoticgd
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * */

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
