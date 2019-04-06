/* ###
 * IP: GHIDRA
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
package gotools;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Stream;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataStub;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this analyzer
 * does.
 */
public class GotoolsAnalyzer extends AbstractAnalyzer {

	public GotoolsAnalyzer() {

		// TODO: Name the analyzer and give it a description.

		super("Go Tools", "Collection of tools to analyze go binaries.", AnalyzerType.BYTE_ANALYZER);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		// Return true if analyzer should be enabled by default
		return true;
	}

	@Override
	public boolean canAnalyze(Program p) {
		try {
			this.getGopclntab(p);
			return true;
		} catch (NotFoundException e) {
			return false;
		}
	}

	@Override
	public void registerOptions(Options options, Program program) {

		// TODO: If this analyzer has custom options, register them here

		options.registerOption("Option name goes here", false, null, "Option description goes here");
	}

	private Symbol findAndInsertRuntimeMoreStack(Program p, TaskMonitor monitor)
			throws NotFoundException, CancelledException {
		List<Symbol> s = p.getSymbolTable().getGlobalSymbols("runtime.morestack");
		if (s.size() != 0) {
			return s.get(0);
		}
		// opcodes of runtime.morestack()
		// tested on 1.12 64bit
		byte[] morestackSignature = { 0x64, 0x48, (byte) (0x8b), 0x1c, 0x25, (byte) (0xf8), -1, -1, -1, 0x48,
				(byte) (0x8b), 0x5b, 0x30, 0x48, (byte) (0x8b), 0x33, 0x64, 0x48, 0x39, 0x34, 0x25, (byte) (0xf8), -1,
				-1, -1 };
		Address match = p.getMemory().findBytes(null, morestackSignature, null, true, monitor);
		if (match == null) {
			throw new NotFoundException("unable to find runtime.morestack");
		}
		Function f = p.getFunctionManager().getFunctionAt(match);
		if (f != null) {
			try {
				f.setName("runtime.morestack", SourceType.ANALYSIS);
			} catch (DuplicateNameException | InvalidInputException e) {
				e.printStackTrace();
			}
			return f.getSymbol();
		}
		CreateFunctionCmd cmd = new CreateFunctionCmd("runtime.morestack", match, null, SourceType.ANALYSIS);
		if (cmd.applyTo(p, monitor)) {
			return p.getFunctionManager().getFunctionAt(match).getSymbol();
		}
		throw new CancelledException("unable to create function");
	}

	@Override
	public boolean added(Program p, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException {
		MemoryBlock gopcln;
		try {
			gopcln= this.getGopclntab(p);
		} catch (NotFoundException e) {
			log.appendException(e);
			throw new CancelledException("gopclntab not found");
		}
		Symbol s;
		try {
			s = findAndInsertRuntimeMoreStack(p, monitor);
		} catch (NotFoundException e) {
			e.printStackTrace();
			throw new CancelledException();
		}
		traverseXrefsOfMS(p, monitor, log, s);
		try {
			renameFunctions(p, monitor, log, gopcln);
		} catch (MemoryAccessException e) {
			log.appendException(e);
			return false;
		}
		return true;
	}

	private void traverseXrefsOfMS(Program p, TaskMonitor monitor, MessageLog log, Symbol ms) {
		// TODO this function does not yet do anything useful
		for (Reference r : ms.getReferences(monitor)) {
			Function f = p.getFunctionManager().getFunctionContaining(r.getFromAddress());
			if (f != null) {
				// function already exists
				Instruction i1 = p.getListing().getInstructionAt(f.getSymbol().getAddress());
				if (i1 == null)
					continue;
				Instruction i2 = p.getListing().getInstructionAfter(i1.getMaxAddress());
				if (i2.getMnemonicString() != "JMP")
					continue;
				boolean jumpToMS = Stream.of(i2.getReferencesFrom())
						.noneMatch((Reference ref) -> ref.getSymbolID() == ms.getID());
				if (!jumpToMS) {
					continue;
				}
				log.appendMsg("TODO found a jump to runtime ms, ignoring it for now");
				continue;
			}
			// create a function here (warning, the function starts before the address)
			log.appendMsg("TODO found a new function, ignoring it for now");
		}
	}

	/**
	 * Creates a new defined Data object at the given address.
	 * 
	 * @param address  the address at which to create a new Data object.
	 * @param datatype the Data Type that describes the type of Data object to
	 *                 create.
	 * @return the newly created Data object
	 */
	public final Data createData(Program p, Address address, DataType datatype) throws Exception {
		Listing listing = p.getListing();
		Data d = listing.getDefinedDataAt(address);
		if (d != null) {
			if (d.getDataType().isEquivalent(datatype)) {
				return d;
			}
			throw new CodeUnitInsertionException("Data conflict at address " + address);
		}
		return listing.createData(address, datatype);
	}

	private void renameFunctions(Program p, TaskMonitor m, MessageLog log, MemoryBlock gopc)
			throws MemoryAccessException {
		long pointerSize = 8;
		// TODO this only works for 64bit binaries
		Address a = gopc.getStart().add(8); // skip unimportant header
		long size = p.getMemory().getLong(a);
		a = a.add(pointerSize);
		for (int i = 0; i < size; i++) {
			long funcOffset = p.getMemory().getLong(a); // TODO use createDword
			a = a.add(pointerSize);
			long nameOffset = p.getMemory().getLong(a); // TODO use createDword
			a = a.add(pointerSize);
			Address nameGoStrPointer = gopc.getStart().add(nameOffset + pointerSize);
			Address name = gopc.getStart().add(p.getMemory().getInt(nameGoStrPointer));
			Data d;
			try {
				// TODO we probably know the lenght of the string
				d = createData(p, name, new StringDataType());
			} catch (Exception e) {
				log.appendException(e);
				continue;
			}
			Address funcPointer = p.getAddressFactory().getDefaultAddressSpace().getAddress(funcOffset);
			Function f = p.getFunctionManager().getFunctionAt(funcPointer);
			if (f == null) {
				String functionName = (String)(d.getValue());
				if (functionName.startsWith("type..")) {
					// TODO what to do with it?
					p.getListing().setComment(funcPointer, CodeUnit.EOL_COMMENT, functionName);
					continue;
				}
				CreateFunctionCmd cmd = new CreateFunctionCmd(functionName, funcPointer, null, SourceType.ANALYSIS);
				if (!cmd.applyTo(p, m)) {
					log.appendMsg(String.format("Unable to create function at %s, (expected %s)\n", d.getAddress(), d.getValue()));
				}
				continue;
			}
			try {
				f.setName((String)(d.getValue()), SourceType.ANALYSIS);
			} catch (DuplicateNameException | InvalidInputException e) {
				log.appendException(e);
				continue;
			}
		}
	}

	private MemoryBlock getGopclntab(Program p) throws NotFoundException {
		for (MemoryBlock b : p.getMemory().getBlocks()) {
			if (b.getName().equals(".gopclntab")) {
				return b;
			}
		}
		throw new NotFoundException();
	}
}
